// Section 5.2.4: Pharmacy Presentation Verification
//
// Verifies the payloads emitted by Section 5.2.3. The pharmacy uses the BBS
// group public key to verify the genuine authorization certificate; it never
// receives an HP member key or the group-manager opening key.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	mathrand "math/rand"
	"os"
	"runtime"
	"sort"
	"strconv"
	"time"

	bbs04 "eprx-bbs04"
	"github.com/Ethernal-Tech/kryptology/pkg/bulletproof"
	"github.com/Ethernal-Tech/kryptology/pkg/core/curves"
	"github.com/Ethernal-Tech/kryptology/pkg/signatures/bbs"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/gtank/merlin"
)

const (
	numRuns      = 100
	warmupRuns   = 10
	groupKeyFile = "bbs_group_public_key.json"
	resultsFile  = "5.2.4_pharmacy_verification_results.csv"
	authDomain   = "EPRX-AUTH-PRES-v1"
	bbsDomain    = "bbs-prescription-presentation-v1"
	lowerDomain  = "proof-lower-bound-v1"
	upperDomain  = "proof-upper-bound-v1"
	shuffleSeed  = int64(20260712)
	vectorLength = 16
)

type SerializedGroupPublicKey struct {
	G1 string `json:"g1"`
	G2 string `json:"g2"`
	H  string `json:"h"`
	U  string `json:"u"`
	V  string `json:"v"`
	W  string `json:"w"`
}

type SerializedGroupSignature struct {
	T1      string `json:"t1_g1"`
	T2      string `json:"t2_g1"`
	T3      string `json:"t3_g1"`
	C       string `json:"challenge"`
	SAlpha  string `json:"s_alpha"`
	SBeta   string `json:"s_beta"`
	SX      string `json:"s_x"`
	SDelta1 string `json:"s_delta_1"`
	SDelta2 string `json:"s_delta_2"`
}

type AuthorizationCertificate struct {
	EphemeralIssuerPK string                   `json:"ephemeral_issuer_public_key_bbs_plus"`
	IssueTime         int64                    `json:"issue_time"`
	SigmaGrp          SerializedGroupSignature `json:"sigma_grp"`
}

type PresentationPayload struct {
	AuthorizationCertificate AuthorizationCertificate `json:"authorization_certificate"`
	RevealedAttributes       map[string]string        `json:"revealed_attributes"`
	ExpiryCommitment         string                   `json:"expiry_commitment"`
	BBSProof                 string                   `json:"pi_bbs_plus"`
	Nonce                    string                   `json:"nonce"`
	Challenge                string                   `json:"challenge"`
	LowerBoundProof          string                   `json:"pi_lower"`
	UpperBoundProof          string                   `json:"pi_upper"`
	TVer                     int                      `json:"t_ver"`
	LValid                   int                      `json:"L_valid"`
	NTotal                   int                      `json:"n_total"`
	NDisclosed               int                      `json:"n_disclosed"`
	NHidden                  int                      `json:"n_hidden"`
}

type TimingBreakdown struct {
	TotalMS         float64
	AuthorizationMS float64
	BBSProofMS      float64
	LowerBPMS       float64
	UpperBPMS       float64
}

type Summary struct {
	Mean   float64
	SD     float64
	CV     float64
	Median float64
	IQR    float64
}

type Samples struct {
	Total []float64
	Auth  []float64
	BBS   []float64
	Lower []float64
	Upper []float64
}

func mustDecodeHex(value, label string) []byte {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		log.Fatalf("failed to decode %s: %v", label, err)
	}
	return decoded
}

func decodeG1(value, label string) (bls.G1Affine, error) {
	var point bls.G1Affine
	if _, err := point.SetBytes(mustDecodeHex(value, label)); err != nil {
		return point, fmt.Errorf("cannot decode %s: %w", label, err)
	}
	if !point.IsOnCurve() || !point.IsInSubGroup() {
		return point, fmt.Errorf("%s is not a valid G1 subgroup point", label)
	}
	return point, nil
}

func decodeG2(value, label string) (bls.G2Affine, error) {
	var point bls.G2Affine
	if _, err := point.SetBytes(mustDecodeHex(value, label)); err != nil {
		return point, fmt.Errorf("cannot decode %s: %w", label, err)
	}
	if !point.IsOnCurve() || !point.IsInSubGroup() {
		return point, fmt.Errorf("%s is not a valid G2 subgroup point", label)
	}
	return point, nil
}

func decodeScalar(value, label string) (fr.Element, error) {
	var scalar fr.Element
	bytes := mustDecodeHex(value, label)
	if len(bytes) != fr.Bytes {
		return scalar, fmt.Errorf("%s must contain %d bytes", label, fr.Bytes)
	}
	if err := scalar.SetBytesCanonical(bytes); err != nil {
		return scalar, fmt.Errorf("cannot decode %s: %w", label, err)
	}
	return scalar, nil
}

func loadGroupPublicKey() (*bbs04.GroupPublicKey, error) {
	encoded, err := os.ReadFile(groupKeyFile)
	if err != nil {
		return nil, err
	}
	var serialized SerializedGroupPublicKey
	if err = json.Unmarshal(encoded, &serialized); err != nil {
		return nil, err
	}
	g1, err := decodeG1(serialized.G1, "group public key g1")
	if err != nil {
		return nil, err
	}
	g2, err := decodeG2(serialized.G2, "group public key g2")
	if err != nil {
		return nil, err
	}
	h, err := decodeG1(serialized.H, "group public key h")
	if err != nil {
		return nil, err
	}
	u, err := decodeG1(serialized.U, "group public key u")
	if err != nil {
		return nil, err
	}
	v, err := decodeG1(serialized.V, "group public key v")
	if err != nil {
		return nil, err
	}
	w, err := decodeG2(serialized.W, "group public key w")
	if err != nil {
		return nil, err
	}
	return &bbs04.GroupPublicKey{G1: g1, G2: g2, H: h, U: u, V: v, W: w}, nil
}

func decodeGroupSignature(serialized SerializedGroupSignature) (*bbs04.GroupSignature, error) {
	t1, err := decodeG1(serialized.T1, "group signature T1")
	if err != nil {
		return nil, err
	}
	t2, err := decodeG1(serialized.T2, "group signature T2")
	if err != nil {
		return nil, err
	}
	t3, err := decodeG1(serialized.T3, "group signature T3")
	if err != nil {
		return nil, err
	}
	c, err := decodeScalar(serialized.C, "group signature challenge")
	if err != nil {
		return nil, err
	}
	sAlpha, err := decodeScalar(serialized.SAlpha, "group signature s_alpha")
	if err != nil {
		return nil, err
	}
	sBeta, err := decodeScalar(serialized.SBeta, "group signature s_beta")
	if err != nil {
		return nil, err
	}
	sx, err := decodeScalar(serialized.SX, "group signature s_x")
	if err != nil {
		return nil, err
	}
	sDelta1, err := decodeScalar(serialized.SDelta1, "group signature s_delta_1")
	if err != nil {
		return nil, err
	}
	sDelta2, err := decodeScalar(serialized.SDelta2, "group signature s_delta_2")
	if err != nil {
		return nil, err
	}
	return &bbs04.GroupSignature{
		T1: t1, T2: t2, T3: t3, C: c,
		SAlpha: sAlpha, SBeta: sBeta, SX: sx,
		SDelta1: sDelta1, SDelta2: sDelta2,
	}, nil
}

func authorizationMessage(issuerPublicKey []byte, issueTime int64) []byte {
	message := make([]byte, 0, len(authDomain)+4+len(issuerPublicKey)+8)
	message = append(message, []byte(authDomain)...)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(issuerPublicKey)))
	message = append(message, length[:]...)
	message = append(message, issuerPublicKey...)
	var timestamp [8]byte
	binary.BigEndian.PutUint64(timestamp[:], uint64(issueTime))
	message = append(message, timestamp[:]...)
	return message
}

func verifyOnce(
	payload *PresentationPayload,
	groupPublicKey *bbs04.GroupPublicKey,
) (TimingBreakdown, error) {
	curveBBS := curves.BLS12381(&curves.PointBls12381G2{})
	curveBP := curves.ED25519()
	startTotal := time.Now()

	// 1. Verify the genuine BBS group-signature authorization certificate.
	startAuthorization := time.Now()
	issuerPublicKeyBytes := mustDecodeHex(
		payload.AuthorizationCertificate.EphemeralIssuerPK,
		"ephemeral issuer public key",
	)
	groupSignature, err := decodeGroupSignature(payload.AuthorizationCertificate.SigmaGrp)
	if err != nil {
		return TimingBreakdown{}, err
	}
	authMessage := authorizationMessage(
		issuerPublicKeyBytes,
		payload.AuthorizationCertificate.IssueTime,
	)
	if !bbs04.Verify(groupPublicKey, authMessage, groupSignature) {
		return TimingBreakdown{}, fmt.Errorf("BBS group-signature authorization verification failed")
	}
	authorizationDuration := time.Since(startAuthorization)

	// 2. Verify the BBS+ selective-disclosure presentation proof.
	startBBS := time.Now()
	issuerPublicKey := new(bbs.PublicKey).Init(curveBBS)
	if err = issuerPublicKey.UnmarshalBinary(issuerPublicKeyBytes); err != nil {
		return TimingBreakdown{}, fmt.Errorf("cannot unmarshal BBS+ issuer key: %w", err)
	}
	if payload.NTotal != 6 {
		return TimingBreakdown{}, fmt.Errorf("expected six signed messages, received %d", payload.NTotal)
	}
	messageGenerators, err := new(bbs.MessageGenerators).Init(issuerPublicKey, payload.NTotal)
	if err != nil {
		return TimingBreakdown{}, err
	}

	revealedMessages := make(map[int]curves.Scalar)
	attributeOrder := []string{"holder", "rx_id", "patient_reference", "medication", "dosage"}
	for index, name := range attributeOrder {
		if value, present := payload.RevealedAttributes[name]; present {
			revealedMessages[index] = curveBBS.Scalar.Hash([]byte(name + ":" + value))
		}
	}
	commitmentBytes := mustDecodeHex(payload.ExpiryCommitment, "expiry commitment")
	commitmentHash := sha256.Sum256(commitmentBytes)
	revealedMessages[5] = curveBBS.Scalar.Hash(commitmentHash[:])

	bbsProofBytes := mustDecodeHex(payload.BBSProof, "BBS+ presentation proof")
	bbsProof := new(bbs.PokSignatureProof).Init(curveBBS)
	if err = bbsProof.UnmarshalBinary(bbsProofBytes); err != nil {
		return TimingBreakdown{}, fmt.Errorf("cannot unmarshal BBS+ proof: %w", err)
	}
	nonceBytes := mustDecodeHex(payload.Nonce, "verifier nonce")
	nonce, err := curveBBS.Scalar.SetBytes(nonceBytes)
	if err != nil {
		return TimingBreakdown{}, fmt.Errorf("cannot reconstruct verifier nonce: %w", err)
	}
	challengeBytes := mustDecodeHex(payload.Challenge, "BBS+ challenge")
	challenge, err := curveBBS.Scalar.SetBytes(challengeBytes)
	if err != nil {
		return TimingBreakdown{}, fmt.Errorf("cannot reconstruct BBS+ challenge: %w", err)
	}
	verificationTranscript := merlin.NewTranscript(bbsDomain)
	if !bbsProof.Verify(
		revealedMessages,
		issuerPublicKey,
		messageGenerators,
		nonce,
		challenge,
		verificationTranscript,
	) {
		return TimingBreakdown{}, fmt.Errorf("BBS+ presentation-proof verification failed")
	}
	bbsDuration := time.Since(startBBS)

	// 3. Verify lower- and upper-bound Bulletproofs using the same generators,
	// transcript domains, and public policy inputs used by the patient.
	generatorG := curveBP.Point.Hash([]byte("EPRX-expiry-generator-G-v1"))
	generatorH := curveBP.Point.Hash([]byte("EPRX-expiry-generator-H-v1"))
	generatorU := curveBP.Point.Hash([]byte("EPRX-expiry-generator-U-v1"))
	bpGenerators := bulletproof.NewRangeProofGenerators(generatorG, generatorH, generatorU)
	rangeVerifier, err := bulletproof.NewRangeVerifier(
		vectorLength,
		[]byte("range-v1"),
		[]byte("ipp-v1"),
		*curveBP,
	)
	if err != nil {
		return TimingBreakdown{}, err
	}
	commitmentCE, err := curveBP.Point.FromAffineCompressed(commitmentBytes)
	if err != nil {
		return TimingBreakdown{}, fmt.Errorf("cannot decode expiry commitment: %w", err)
	}
	commitmentDelta := commitmentCE.Sub(generatorG.Mul(curveBP.Scalar.New(payload.TVer)))

	lowerProof := bulletproof.NewRangeProof(curveBP)
	if err = lowerProof.UnmarshalBinary(mustDecodeHex(payload.LowerBoundProof, "lower Bulletproof")); err != nil {
		return TimingBreakdown{}, fmt.Errorf("cannot unmarshal lower Bulletproof: %w", err)
	}
	startLower := time.Now()
	lowerTranscript := merlin.NewTranscript(lowerDomain)
	lowerValid, err := rangeVerifier.Verify(
		lowerProof,
		commitmentDelta,
		bpGenerators,
		vectorLength,
		lowerTranscript,
	)
	if err != nil || !lowerValid {
		return TimingBreakdown{}, fmt.Errorf("lower Bulletproof verification failed: %v", err)
	}
	lowerDuration := time.Since(startLower)

	upperCommitment := generatorG.Mul(curveBP.Scalar.New(payload.LValid)).Sub(commitmentDelta)
	upperProof := bulletproof.NewRangeProof(curveBP)
	if err = upperProof.UnmarshalBinary(mustDecodeHex(payload.UpperBoundProof, "upper Bulletproof")); err != nil {
		return TimingBreakdown{}, fmt.Errorf("cannot unmarshal upper Bulletproof: %w", err)
	}
	startUpper := time.Now()
	upperTranscript := merlin.NewTranscript(upperDomain)
	upperValid, err := rangeVerifier.Verify(
		upperProof,
		upperCommitment,
		bpGenerators,
		vectorLength,
		upperTranscript,
	)
	if err != nil || !upperValid {
		return TimingBreakdown{}, fmt.Errorf("upper Bulletproof verification failed: %v", err)
	}
	upperDuration := time.Since(startUpper)

	return TimingBreakdown{
		TotalMS:         float64(time.Since(startTotal).Nanoseconds()) / 1e6,
		AuthorizationMS: float64(authorizationDuration.Nanoseconds()) / 1e6,
		BBSProofMS:      float64(bbsDuration.Nanoseconds()) / 1e6,
		LowerBPMS:       float64(lowerDuration.Nanoseconds()) / 1e6,
		UpperBPMS:       float64(upperDuration.Nanoseconds()) / 1e6,
	}, nil
}

func summarize(values []float64) Summary {
	ordered := append([]float64(nil), values...)
	sort.Float64s(ordered)
	var total float64
	for _, value := range ordered {
		total += value
	}
	mean := total / float64(len(ordered))
	var squared float64
	for _, value := range ordered {
		difference := value - mean
		squared += difference * difference
	}
	sd := math.Sqrt(squared / float64(len(ordered)-1))
	median := func(values []float64) float64 {
		length := len(values)
		if length%2 == 1 {
			return values[length/2]
		}
		return (values[length/2-1] + values[length/2]) / 2
	}
	middle := len(ordered) / 2
	q1 := median(ordered[:middle])
	q3 := median(ordered[middle:])
	return Summary{Mean: mean, SD: sd, CV: 100 * sd / mean, Median: median(ordered), IQR: q3 - q1}
}

func average(values []float64) float64 {
	var total float64
	for _, value := range values {
		total += value
	}
	return total / float64(len(values))
}

func loadPayloadPool(filename string, expected int) ([]PresentationPayload, error) {
	encoded, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var payloads []PresentationPayload
	if err = json.Unmarshal(encoded, &payloads); err != nil {
		return nil, err
	}
	if len(payloads) != expected {
		return nil, fmt.Errorf("%s contains %d payloads; expected %d", filename, len(payloads), expected)
	}
	return payloads, nil
}

func main() {
	runtime.GOMAXPROCS(1)
	groupPublicKey, err := loadGroupPublicKey()
	if err != nil {
		log.Fatal("cannot load BBS group public key:", err)
	}

	payloads := make(map[int][]PresentationPayload, 5)
	warmupPayloads := make(map[int][]PresentationPayload, 5)
	samples := make(map[int]*Samples, 5)
	for disclosed := 1; disclosed <= 5; disclosed++ {
		payloads[disclosed], err = loadPayloadPool(fmt.Sprintf("presentation_payloads_%d.json", disclosed), numRuns)
		if err != nil {
			log.Fatal(err)
		}
		warmupPayloads[disclosed], err = loadPayloadPool(fmt.Sprintf("presentation_warmup_payloads_%d.json", disclosed), warmupRuns)
		if err != nil {
			log.Fatal(err)
		}
		samples[disclosed] = &Samples{}
		for warmup := 0; warmup < warmupRuns; warmup++ {
			if _, err = verifyOnce(&warmupPayloads[disclosed][warmup], groupPublicKey); err != nil {
				log.Fatal(err)
			}
		}
	}
	runtime.GC() // Once before the complete measurement phase, never per verification.

	// Interleave configurations in a reproducibly shuffled order per round.
	rng := mathrand.New(mathrand.NewSource(shuffleSeed))
	for round := 0; round < numRuns; round++ {
		order := []int{1, 2, 3, 4, 5}
		rng.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
		for _, disclosed := range order {
			timing, verifyErr := verifyOnce(&payloads[disclosed][round], groupPublicKey)
			if verifyErr != nil {
				log.Fatal(verifyErr)
			}
			sample := samples[disclosed]
			sample.Total = append(sample.Total, timing.TotalMS)
			sample.Auth = append(sample.Auth, timing.AuthorizationMS)
			sample.BBS = append(sample.BBS, timing.BBSProofMS)
			sample.Lower = append(sample.Lower, timing.LowerBPMS)
			sample.Upper = append(sample.Upper, timing.UpperBPMS)
		}
	}

	file, err := os.Create(resultsFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()
	writer.Write([]string{
		"n_disclosed", "n_hidden", "runs", "mean_total_ms", "stddev_total_ms",
		"cv_percent", "median_total_ms", "iqr_total_ms", "mean_auth_verify_ms",
		"mean_bbs_proof_verify_ms", "mean_lower_bp_verify_ms",
		"mean_upper_bp_verify_ms", "gomaxprocs",
	})

	for disclosed := 1; disclosed <= 5; disclosed++ {
		sample := samples[disclosed]
		summary := summarize(sample.Total)
		writer.Write([]string{
			strconv.Itoa(disclosed), strconv.Itoa(5 - disclosed), strconv.Itoa(numRuns),
			fmt.Sprintf("%.3f", summary.Mean), fmt.Sprintf("%.3f", summary.SD),
			fmt.Sprintf("%.3f", summary.CV), fmt.Sprintf("%.3f", summary.Median),
			fmt.Sprintf("%.3f", summary.IQR), fmt.Sprintf("%.3f", average(sample.Auth)),
			fmt.Sprintf("%.3f", average(sample.BBS)), fmt.Sprintf("%.3f", average(sample.Lower)),
			fmt.Sprintf("%.3f", average(sample.Upper)), strconv.Itoa(runtime.GOMAXPROCS(0)),
		})
		fmt.Printf("N_disclosed=%d, mean=%.3f ms, SD=%.3f ms, CV=%.2f%%, median=%.3f ms, IQR=%.3f ms\n",
			disclosed, summary.Mean, summary.SD, summary.CV, summary.Median, summary.IQR)
	}
	writer.Flush()
	if err = writer.Error(); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Results written to %s.\n", resultsFile)
}
