// Section 5.2.3: Patient Presentation Generation
//
// Consumes the six-message patient_wallet.json emitted by Section 5.2.2.
// The genuine BBS group-signature authorization certificate is carried in the
// presentation payload but is not generated or verified by the patient.
package main

import (
	crand "crypto/rand"
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

	"github.com/Ethernal-Tech/kryptology/pkg/bulletproof"
	"github.com/Ethernal-Tech/kryptology/pkg/core/curves"
	"github.com/Ethernal-Tech/kryptology/pkg/signatures/bbs"
	"github.com/Ethernal-Tech/kryptology/pkg/signatures/common"
	"github.com/gtank/merlin"
)

const (
	numRuns      = 100
	warmupRuns   = 10
	walletFile   = "patient_wallet.json"
	resultsFile  = "5.2.3_patient_presentation_results.csv"
	bbsDomain    = "bbs-prescription-presentation-v1"
	lowerDomain  = "proof-lower-bound-v1"
	upperDomain  = "proof-upper-bound-v1"
	challengeTag = "signature proof of knowledge"
)

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

type Credential struct {
	ExpiryCommitment string            `json:"expiry_commitment"`
	BBSPlusSignature string            `json:"bbs_plus_signature"`
	Attributes       map[string]string `json:"attributes"`
}

type CommitmentOpening struct {
	ExpiryEpochDays int    `json:"m_exp"`
	BlindingFactor  string `json:"r"`
}

type PatientWallet struct {
	Credential               Credential               `json:"credential"`
	AuthorizationCertificate AuthorizationCertificate `json:"authorization_certificate"`
	CommitmentOpening        CommitmentOpening        `json:"commitment_opening"`
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
	TotalGenerationMS     float64
	BBSProofGenerationMS  float64
	LowerBulletproofGenMS float64
	UpperBulletproofGenMS float64
}

type Summary struct {
	Mean   float64
	SD     float64
	CV     float64
	Median float64
	IQR    float64
}

var orderedAttributeNames = []string{
	"holder",
	"rx_id",
	"patient_reference",
	"medication",
	"dosage",
}

func summarize(values []float64) Summary {
	ordered := append([]float64(nil), values...)
	sort.Float64s(ordered)

	var total float64
	for _, value := range ordered {
		total += value
	}
	mean := total / float64(len(ordered))

	var squaredDeviation float64
	for _, value := range ordered {
		difference := value - mean
		squaredDeviation += difference * difference
	}
	sd := 0.0
	if len(ordered) > 1 {
		sd = math.Sqrt(squaredDeviation / float64(len(ordered)-1))
	}

	medianOfSorted := func(sortedValues []float64) float64 {
		length := len(sortedValues)
		if length%2 == 1 {
			return sortedValues[length/2]
		}
		return (sortedValues[length/2-1] + sortedValues[length/2]) / 2
	}

	median := medianOfSorted(ordered)
	midpoint := len(ordered) / 2
	lowerHalf := ordered[:midpoint]
	upperHalf := ordered[midpoint:]
	if len(ordered)%2 == 1 {
		upperHalf = ordered[midpoint+1:]
	}
	q1 := medianOfSorted(lowerHalf)
	q3 := medianOfSorted(upperHalf)

	cv := 0.0
	if mean != 0 {
		cv = 100 * sd / mean
	}
	return Summary{Mean: mean, SD: sd, CV: cv, Median: median, IQR: q3 - q1}
}

func mustDecodeHex(value, label string) []byte {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		log.Fatalf("failed to decode %s: %v", label, err)
	}
	return decoded
}

func requireWalletFields(wallet *PatientWallet) {
	if wallet.AuthorizationCertificate.EphemeralIssuerPK == "" {
		log.Fatal("wallet is missing the ephemeral BBS+ issuer public key")
	}
	if wallet.AuthorizationCertificate.SigmaGrp.T1 == "" {
		log.Fatal("wallet is missing the structured BBS group signature")
	}
	if wallet.Credential.ExpiryCommitment == "" {
		log.Fatal("wallet is missing the expiry commitment")
	}
	if wallet.Credential.BBSPlusSignature == "" {
		log.Fatal("wallet is missing the BBS+ credential signature")
	}
	for _, name := range orderedAttributeNames {
		if wallet.Credential.Attributes[name] == "" {
			log.Fatalf("wallet is missing signed attribute %q", name)
		}
	}
	if wallet.Credential.Attributes["expiry_commitment_hash"] == "" {
		log.Fatal("wallet is missing the signed expiry-commitment hash")
	}
}

func freshVerifierNonce() []byte {
	curveBBS := curves.BLS12381(&curves.PointBls12381G2{})
	wide := make([]byte, 64)
	if _, err := crand.Read(wide); err != nil {
		log.Fatal("cannot generate verifier nonce:", err)
	}
	nonce, err := curveBBS.Scalar.SetBytesWide(wide)
	if err != nil {
		log.Fatal("cannot reduce verifier nonce:", err)
	}
	return nonce.Bytes()
}

func generatePresentationOnce(
	wallet *PatientWallet,
	nDisclosed int,
	verifierNonce []byte,
) (TimingBreakdown, PresentationPayload, error) {
	if nDisclosed < 1 || nDisclosed > 5 {
		return TimingBreakdown{}, PresentationPayload{}, fmt.Errorf("nDisclosed must be in {1,2,3,4,5}")
	}

	curveBBS := curves.BLS12381(&curves.PointBls12381G2{})
	curveBP := curves.ED25519()
	startTotal := time.Now()

	issuerPublicKeyBytes := mustDecodeHex(
		wallet.AuthorizationCertificate.EphemeralIssuerPK,
		"issuer public key",
	)
	issuerPublicKey := new(bbs.PublicKey).Init(curveBBS)
	if err := issuerPublicKey.UnmarshalBinary(issuerPublicKeyBytes); err != nil {
		return TimingBreakdown{}, PresentationPayload{}, fmt.Errorf("cannot unmarshal issuer public key: %w", err)
	}

	bbsSignatureBytes := mustDecodeHex(wallet.Credential.BBSPlusSignature, "BBS+ signature")
	bbsSignature := new(bbs.Signature).Init(curveBBS)
	if err := bbsSignature.UnmarshalBinary(bbsSignatureBytes); err != nil {
		return TimingBreakdown{}, PresentationPayload{}, fmt.Errorf("cannot unmarshal BBS+ signature: %w", err)
	}

	commitmentBytes := mustDecodeHex(wallet.Credential.ExpiryCommitment, "expiry commitment")
	commitmentHash := sha256.Sum256(commitmentBytes)
	if hex.EncodeToString(commitmentHash[:]) != wallet.Credential.Attributes["expiry_commitment_hash"] {
		return TimingBreakdown{}, PresentationPayload{}, fmt.Errorf("expiry commitment does not match signed commitment hash")
	}

	messages := make([]curves.Scalar, 0, 6)
	for _, name := range orderedAttributeNames {
		value := wallet.Credential.Attributes[name]
		messages = append(messages, curveBBS.Scalar.Hash([]byte(name+":"+value)))
	}
	messages = append(messages, curveBBS.Scalar.Hash(commitmentHash[:]))
	nTotal := len(messages)

	messageGenerators, err := new(bbs.MessageGenerators).Init(issuerPublicKey, nTotal)
	if err != nil {
		return TimingBreakdown{}, PresentationPayload{}, err
	}
	proofMessages := make([]common.ProofMessage, 0, nTotal)
	for index, message := range messages {
		// The expiry-commitment hash (index 5) is always disclosed because the
		// verifier deterministically derives it from the presented commitment.
		if index < nDisclosed || index == 5 {
			proofMessages = append(proofMessages, &common.RevealedMessage{Message: message})
		} else {
			proofMessages = append(proofMessages, &common.ProofSpecificMessage{Message: message})
		}
	}

	startBBS := time.Now()
	pok, err := bbs.NewPokSignature(
		bbsSignature,
		messageGenerators,
		proofMessages,
		crand.Reader,
	)
	if err != nil {
		return TimingBreakdown{}, PresentationPayload{}, err
	}
	bbsTranscript := merlin.NewTranscript(bbsDomain)
	pok.GetChallengeContribution(bbsTranscript)
	bbsTranscript.AppendMessage([]byte("nonce"), verifierNonce)
	challengeBytes := bbsTranscript.ExtractBytes([]byte(challengeTag), 64)
	challenge, err := curveBBS.Scalar.SetBytesWide(challengeBytes)
	if err != nil {
		return TimingBreakdown{}, PresentationPayload{}, err
	}
	bbsProof, err := pok.GenerateProof(challenge)
	if err != nil {
		return TimingBreakdown{}, PresentationPayload{}, err
	}
	bbsProofBytes, err := bbsProof.MarshalBinary()
	if err != nil {
		return TimingBreakdown{}, PresentationPayload{}, err
	}
	bbsProofDuration := time.Since(startBBS)

	mExp := wallet.CommitmentOpening.ExpiryEpochDays
	blindingBytes := mustDecodeHex(wallet.CommitmentOpening.BlindingFactor, "blinding factor")
	blindingFactor, err := curveBP.Scalar.SetBytes(blindingBytes)
	if err != nil {
		return TimingBreakdown{}, PresentationPayload{}, fmt.Errorf("cannot reconstruct blinding factor: %w", err)
	}

	tVer := 20630
	lValid := 365
	remainingDays := mExp - tVer
	if remainingDays < 0 || remainingDays > lValid {
		return TimingBreakdown{}, PresentationPayload{}, fmt.Errorf("remaining validity is outside [0,L_valid]")
	}

	const vectorLength = 16
	// These domains exactly match the commitment generators used in 5.2.2.
	generatorG := curveBP.Point.Hash([]byte("EPRX-expiry-generator-G-v1"))
	generatorH := curveBP.Point.Hash([]byte("EPRX-expiry-generator-H-v1"))
	generatorU := curveBP.Point.Hash([]byte("EPRX-expiry-generator-U-v1"))
	bpGenerators := bulletproof.NewRangeProofGenerators(generatorG, generatorH, generatorU)
	rangeProver, err := bulletproof.NewRangeProver(
		vectorLength,
		[]byte("range-v1"),
		[]byte("ipp-v1"),
		*curveBP,
	)
	if err != nil {
		return TimingBreakdown{}, PresentationPayload{}, err
	}

	startLower := time.Now()
	lowerTranscript := merlin.NewTranscript(lowerDomain)
	lowerProof, err := rangeProver.Prove(
		curveBP.Scalar.New(remainingDays),
		blindingFactor,
		vectorLength,
		bpGenerators,
		lowerTranscript,
	)
	if err != nil {
		return TimingBreakdown{}, PresentationPayload{}, err
	}
	lowerDuration := time.Since(startLower)

	startUpper := time.Now()
	upperTranscript := merlin.NewTranscript(upperDomain)
	upperProof, err := rangeProver.Prove(
		curveBP.Scalar.New(lValid-remainingDays),
		blindingFactor.Neg(),
		vectorLength,
		bpGenerators,
		upperTranscript,
	)
	if err != nil {
		return TimingBreakdown{}, PresentationPayload{}, err
	}
	upperDuration := time.Since(startUpper)

	revealedAttributes := make(map[string]string, nDisclosed)
	for index := 0; index < nDisclosed; index++ {
		name := orderedAttributeNames[index]
		revealedAttributes[name] = wallet.Credential.Attributes[name]
	}
	payload := PresentationPayload{
		AuthorizationCertificate: wallet.AuthorizationCertificate,
		RevealedAttributes:       revealedAttributes,
		ExpiryCommitment:         wallet.Credential.ExpiryCommitment,
		BBSProof:                 hex.EncodeToString(bbsProofBytes),
		Nonce:                    hex.EncodeToString(verifierNonce),
		Challenge:                hex.EncodeToString(challenge.Bytes()),
		LowerBoundProof:          hex.EncodeToString(lowerProof.MarshalBinary()),
		UpperBoundProof:          hex.EncodeToString(upperProof.MarshalBinary()),
		TVer:                     tVer,
		LValid:                   lValid,
		NTotal:                   nTotal,
		NDisclosed:               nDisclosed,
		NHidden:                  5 - nDisclosed,
	}
	totalDuration := time.Since(startTotal)
	return TimingBreakdown{
		TotalGenerationMS:     float64(totalDuration.Nanoseconds()) / 1e6,
		BBSProofGenerationMS:  float64(bbsProofDuration.Nanoseconds()) / 1e6,
		LowerBulletproofGenMS: float64(lowerDuration.Nanoseconds()) / 1e6,
		UpperBulletproofGenMS: float64(upperDuration.Nanoseconds()) / 1e6,
	}, payload, nil
}

func main() {
	runtime.GOMAXPROCS(1)

	walletBytes, err := os.ReadFile(walletFile)
	if err != nil {
		log.Fatal("cannot read patient wallet:", err)
	}
	var wallet PatientWallet
	if err = json.Unmarshal(walletBytes, &wallet); err != nil {
		log.Fatal("cannot parse patient wallet:", err)
	}
	requireWalletFields(&wallet)

	file, err := os.Create(resultsFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()
	if err = writer.Write([]string{
		"n_disclosed", "n_hidden", "runs", "mean_total_ms", "stddev_total_ms",
		"cv_percent", "median_total_ms", "iqr_total_ms", "mean_bbs_proof_ms",
		"mean_lower_bulletproof_ms", "mean_upper_bulletproof_ms", "gomaxprocs",
	}); err != nil {
		log.Fatal(err)
	}

	warmupPayloads := make(map[int][]PresentationPayload, 5)
	// Give every configuration an equal untimed warm-up before the
	// randomized, interleaved measurement rounds.
	for nDisclosed := 1; nDisclosed <= 5; nDisclosed++ {
		for warmup := 0; warmup < warmupRuns; warmup++ {
			_, payload, warmupErr := generatePresentationOnce(
				&wallet,
				nDisclosed,
				freshVerifierNonce(),
			)
			if warmupErr != nil {
				log.Fatal(warmupErr)
			}
			warmupPayloads[nDisclosed] = append(warmupPayloads[nDisclosed], payload)
		}

	}

	totalTimings := make(map[int][]float64, 5)
	bbsTotals := make(map[int]float64, 5)
	lowerTotals := make(map[int]float64, 5)
	upperTotals := make(map[int]float64, 5)
	measuredPayloads := make(map[int][]PresentationPayload, 5)
	var seedBytes [8]byte
	if _, err = crand.Read(seedBytes[:]); err != nil {
		log.Fatal(err)
	}
	rng := mathrand.New(mathrand.NewSource(int64(binary.LittleEndian.Uint64(seedBytes[:]))))

	for round := 0; round < numRuns; round++ {
		order := []int{1, 2, 3, 4, 5}
		rng.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
		for _, nDisclosed := range order {
			timing, payload, runErr := generatePresentationOnce(
				&wallet,
				nDisclosed,
				freshVerifierNonce(),
			)
			if runErr != nil {
				log.Fatal(runErr)
			}
			totalTimings[nDisclosed] = append(totalTimings[nDisclosed], timing.TotalGenerationMS)
			bbsTotals[nDisclosed] += timing.BBSProofGenerationMS
			lowerTotals[nDisclosed] += timing.LowerBulletproofGenMS
			upperTotals[nDisclosed] += timing.UpperBulletproofGenMS
			measuredPayloads[nDisclosed] = append(measuredPayloads[nDisclosed], payload)
		}
	}

	for nDisclosed := 1; nDisclosed <= 5; nDisclosed++ {
		payloadFilename := fmt.Sprintf("presentation_payloads_%d.json", nDisclosed)
		payloadBytes, marshalErr := json.MarshalIndent(measuredPayloads[nDisclosed], "", "  ")
		if marshalErr != nil {
			log.Fatal(marshalErr)
		}
		if err = os.WriteFile(payloadFilename, payloadBytes, 0o644); err != nil {
			log.Fatal(err)
		}
		if nDisclosed == 1 {
			singleBytes, singleErr := json.MarshalIndent(measuredPayloads[nDisclosed][0], "", "  ")
			if singleErr != nil {
				log.Fatal(singleErr)
			}
			if err = os.WriteFile("presentation_payload_1.json", singleBytes, 0o644); err != nil {
				log.Fatal(err)
			}
		}
		warmupFilename := fmt.Sprintf("presentation_warmup_payloads_%d.json", nDisclosed)
		warmupBytes, marshalErr := json.MarshalIndent(warmupPayloads[nDisclosed], "", "  ")
		if marshalErr != nil {
			log.Fatal(marshalErr)
		}
		if err = os.WriteFile(warmupFilename, warmupBytes, 0o644); err != nil {
			log.Fatal(err)
		}

		summary := summarize(totalTimings[nDisclosed])
		row := []string{
			strconv.Itoa(nDisclosed),
			strconv.Itoa(5 - nDisclosed),
			strconv.Itoa(numRuns),
			fmt.Sprintf("%.3f", summary.Mean),
			fmt.Sprintf("%.3f", summary.SD),
			fmt.Sprintf("%.3f", summary.CV),
			fmt.Sprintf("%.3f", summary.Median),
			fmt.Sprintf("%.3f", summary.IQR),
			fmt.Sprintf("%.3f", bbsTotals[nDisclosed]/numRuns),
			fmt.Sprintf("%.3f", lowerTotals[nDisclosed]/numRuns),
			fmt.Sprintf("%.3f", upperTotals[nDisclosed]/numRuns),
			strconv.Itoa(runtime.GOMAXPROCS(0)),
		}
		if err = writer.Write(row); err != nil {
			log.Fatal(err)
		}
		fmt.Printf(
			"N_disclosed=%d, mean=%.3f ms, SD=%.3f ms, CV=%.2f%%, median=%.3f ms, IQR=%.3f ms\n",
			nDisclosed,
			summary.Mean,
			summary.SD,
			summary.CV,
			summary.Median,
			summary.IQR,
		)
	}
	fmt.Printf("Measurement order: %d randomized interleaved rounds across all configurations.\n", numRuns)

	writer.Flush()
	if err = writer.Error(); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Results written to %s.\n", resultsFile)
}
