// Section 5.2.2: Prescription Credential Issuance
//
// This research benchmark measures the complete cryptographic issuance
// workflow, including a genuine BBS group signature over the ephemeral BBS+
// issuer public key and issuance timestamp. Group setup and HP member-key
// issuance are offline administrative operations and are therefore excluded
// from the per-prescription timing boundary.
package main

import (
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	mathrand "math/rand"
	"os"
	"runtime"
	"sort"
	"strconv"
	"time"

	bbs04 "eprx-bbs04"
	"github.com/Ethernal-Tech/kryptology/pkg/core/curves"
	"github.com/Ethernal-Tech/kryptology/pkg/signatures/bbs"
)

const (
	runs              = 100
	warmupRuns        = 20
	authDomain        = "EPRX-AUTH-PRES-v1"
	resultsCSV        = "5.2.2_prescription_issuance_results.csv"
	rawResultsCSV     = "5.2.2_prescription_issuance_raw.csv"
	samplePackageJSON = "prescription_package.json"
)

var attributeCounts = []int{4, 6, 8, 10, 12}

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
	BBSPlusSignature string            `json:"bbs_plus_signature"`
	Attributes       map[string]string `json:"attributes"`
}

type CommitmentOpening struct {
	ExpiryEpochDays int    `json:"m_exp"`
	BlindingFactor  string `json:"r"`
}

type PrescriptionPackage struct {
	Credential               Credential               `json:"credential"`
	AuthorizationCertificate AuthorizationCertificate `json:"authorization_certificate"`
	CommitmentOpening        CommitmentOpening        `json:"commitment_opening"`
}

type timingSummary struct {
	MeanMS   float64
	SDMS     float64
	CV       float64
	MedianMS float64
	IQRMS    float64
}

type componentTimings struct {
	TotalMS, KeyGenerationMS, GroupSignatureMS, ExpiryCommitmentMS float64
	CredentialSigningMS, CredentialVerificationMS                  float64
}

func percentile(sorted []float64, p float64) float64 {
	position := p * float64(len(sorted)-1)
	lower := int(math.Floor(position))
	upper := int(math.Ceil(position))
	if lower == upper {
		return sorted[lower]
	}
	return sorted[lower] + (position-float64(lower))*(sorted[upper]-sorted[lower])
}

func summarize(values []float64) timingSummary {
	var total float64
	for _, value := range values {
		total += value
	}
	mean := total / float64(len(values))

	var squaredDeviation float64
	for _, value := range values {
		difference := value - mean
		squaredDeviation += difference * difference
	}

	standardDeviation := 0.0
	if len(values) > 1 {
		standardDeviation = math.Sqrt(squaredDeviation / float64(len(values)-1))
	}

	coefficientOfVariation := 0.0
	if mean != 0 {
		coefficientOfVariation = 100 * standardDeviation / mean
	}

	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	median, q1, q3 := percentile(sorted, .5), percentile(sorted, .25), percentile(sorted, .75)
	return timingSummary{MeanMS: mean, SDMS: standardDeviation, CV: coefficientOfVariation, MedianMS: median, IQRMS: q3 - q1}
}

// authorizationMessage returns an unambiguous, domain-separated encoding of
// the values authorized by the HP's BBS group signature.
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

func serializeGroupSignature(signature *bbs04.GroupSignature) SerializedGroupSignature {
	t1 := signature.T1.Bytes()
	t2 := signature.T2.Bytes()
	t3 := signature.T3.Bytes()
	c := signature.C.Bytes()
	sAlpha := signature.SAlpha.Bytes()
	sBeta := signature.SBeta.Bytes()
	sX := signature.SX.Bytes()
	sDelta1 := signature.SDelta1.Bytes()
	sDelta2 := signature.SDelta2.Bytes()

	return SerializedGroupSignature{
		T1:      hex.EncodeToString(t1[:]),
		T2:      hex.EncodeToString(t2[:]),
		T3:      hex.EncodeToString(t3[:]),
		C:       hex.EncodeToString(c[:]),
		SAlpha:  hex.EncodeToString(sAlpha[:]),
		SBeta:   hex.EncodeToString(sBeta[:]),
		SX:      hex.EncodeToString(sX[:]),
		SDelta1: hex.EncodeToString(sDelta1[:]),
		SDelta2: hex.EncodeToString(sDelta2[:]),
	}
}

// runIssuanceExperiment executes one complete prescription-credential
// issuance. JSON serialization and file I/O are deliberately outside the
// measured interval because they are not cryptographic operations.
func runIssuanceExperiment(
	nAttr int,
	groupPublicKey *bbs04.GroupPublicKey,
	hpMemberKey *bbs04.MemberKey,
) (componentTimings, *PrescriptionPackage, error) {
	curveBBS := curves.BLS12381(&curves.PointBls12381G2{})
	curveBP := curves.ED25519()

	start := time.Now()

	// Generate a fresh, prescription-specific BBS+ issuer key pair.
	componentStart := time.Now()
	issuerPublicKey, issuerPrivateKey, err := bbs.NewKeys(curveBBS)
	if err != nil {
		return componentTimings{}, nil, err
	}
	issuerPublicKeyBytes, err := issuerPublicKey.MarshalBinary()
	if err != nil {
		return componentTimings{}, nil, err
	}
	keyGenerationMS := float64(time.Since(componentStart).Nanoseconds()) / 1e6

	// Authorize the ephemeral BBS+ issuer key with a genuine BBS group
	// signature generated using the enrolled HP's member key.
	issueTime := time.Now().Unix()
	authMessage := authorizationMessage(issuerPublicKeyBytes, issueTime)
	componentStart = time.Now()
	groupSignature, err := bbs04.Sign(groupPublicKey, hpMemberKey, authMessage)
	if err != nil {
		return componentTimings{}, nil, err
	}
	groupSignatureMS := float64(time.Since(componentStart).Nanoseconds()) / 1e6

	// Construct the expiry commitment over Ed25519.
	componentStart = time.Now()
	expirationDateEpoch := 20818
	expirationScalar := curveBP.Scalar.New(expirationDateEpoch)
	blindingFactor := curveBP.Scalar.Random(crand.Reader)
	generatorG := curveBP.Point.Hash([]byte("EPRX-expiry-generator-G-v1"))
	generatorH := curveBP.Point.Hash([]byte("EPRX-expiry-generator-H-v1"))
	expiryCommitment := generatorG.Mul(expirationScalar).Add(generatorH.Mul(blindingFactor))
	commitmentBytes := expiryCommitment.ToAffineCompressed()
	commitmentHash := sha256.Sum256(commitmentBytes)
	expiryCommitmentMS := float64(time.Since(componentStart).Nanoseconds()) / 1e6

	// Encode the signed BBS+ credential attributes. The final signed message
	// is the hash of the canonical compressed expiry commitment.
	attributes := make(map[string]string, nAttr)
	messages := make([]curves.Scalar, 0, nAttr)
	for i := 0; i < nAttr-1; i++ {
		key := fmt.Sprintf("attr_%02d", i+1)
		value := fmt.Sprintf("attribute-value-%02d", i+1)
		attributes[key] = value
		messages = append(messages, curveBBS.Scalar.Hash([]byte(key+":"+value)))
	}
	attributes["expiry_commitment_hash"] = hex.EncodeToString(commitmentHash[:])
	messages = append(messages, curveBBS.Scalar.Hash(commitmentHash[:]))

	componentStart = time.Now()
	messageGenerators, err := new(bbs.MessageGenerators).Init(issuerPublicKey, len(messages))
	if err != nil {
		return componentTimings{}, nil, err
	}
	bbsPlusSignature, err := issuerPrivateKey.Sign(messageGenerators, messages)
	if err != nil {
		return componentTimings{}, nil, err
	}
	credentialSigningMS := float64(time.Since(componentStart).Nanoseconds()) / 1e6
	componentStart = time.Now()
	if err = issuerPublicKey.Verify(bbsPlusSignature, messageGenerators, messages); err != nil {
		return componentTimings{}, nil, fmt.Errorf("issued BBS+ credential verification failed: %w", err)
	}
	credentialVerificationMS := float64(time.Since(componentStart).Nanoseconds()) / 1e6

	// Stop timing after completion of the cryptographic issuance workflow.
	elapsedMS := float64(time.Since(start).Nanoseconds()) / 1e6

	bbsPlusSignatureBytes, err := bbsPlusSignature.MarshalBinary()
	if err != nil {
		return componentTimings{}, nil, err
	}
	packageOut := &PrescriptionPackage{
		Credential: Credential{
			BBSPlusSignature: hex.EncodeToString(bbsPlusSignatureBytes),
			Attributes:       attributes,
		},
		AuthorizationCertificate: AuthorizationCertificate{
			EphemeralIssuerPK: hex.EncodeToString(issuerPublicKeyBytes),
			IssueTime:         issueTime,
			SigmaGrp:          serializeGroupSignature(groupSignature),
		},
		CommitmentOpening: CommitmentOpening{
			ExpiryEpochDays: expirationDateEpoch,
			BlindingFactor:  hex.EncodeToString(blindingFactor.Bytes()),
		},
	}
	return componentTimings{elapsedMS, keyGenerationMS, groupSignatureMS, expiryCommitmentMS, credentialSigningMS, credentialVerificationMS}, packageOut, nil
}

func writeSamplePackage(sample *PrescriptionPackage) error {
	encoded, err := json.MarshalIndent(sample, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(samplePackageJSON, encoded, 0o644)
}

func main() {
	runtime.GOMAXPROCS(1)

	// BBS group setup and HP member-key issuance are offline enrollment
	// operations and are intentionally excluded from prescription issuance.
	groupPublicKey, groupManagerKey, err := bbs04.Setup()
	if err != nil {
		panic(err)
	}
	hpMemberKey, err := bbs04.IssueMemberKey(groupPublicKey, groupManagerKey)
	if err != nil {
		panic(err)
	}

	// Functional preflight: authorization signatures must verify, reject a
	// modified message, and open to the enrolled HP's member certificate.
	preflightMessage := authorizationMessage([]byte("ephemeral-BBS+-key"), 1)
	preflightSignature, err := bbs04.Sign(groupPublicKey, hpMemberKey, preflightMessage)
	if err != nil {
		panic(err)
	}
	if !bbs04.Verify(groupPublicKey, preflightMessage, preflightSignature) {
		panic("valid BBS group signature rejected")
	}
	if bbs04.Verify(groupPublicKey, append(preflightMessage, 0x01), preflightSignature) {
		panic("modified authorization message accepted")
	}
	openedCertificate, err := bbs04.Open(groupManagerKey, preflightSignature)
	if err != nil || !openedCertificate.Equal(&hpMemberKey.A) {
		panic("BBS group-signature opening failed")
	}

	// Give every configuration an equal untimed warm-up before measurement.
	for _, nAttr := range attributeCounts {
		for i := 0; i < warmupRuns; i++ {
			if _, _, err = runIssuanceExperiment(nAttr, groupPublicKey, hpMemberKey); err != nil {
				panic(err)
			}
		}
	}

	file, err := os.Create(resultsCSV)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()
	if err = writer.Write([]string{
		"n_attr", "runs", "mean_ms", "stddev_ms", "cv_percent", "median_ms", "iqr_ms",
		"group_signature_bytes", "gomaxprocs",
	}); err != nil {
		panic(err)
	}
	rawFile, err := os.Create(rawResultsCSV)
	if err != nil {
		panic(err)
	}
	defer rawFile.Close()
	rawWriter := csv.NewWriter(rawFile)
	defer rawWriter.Flush()
	if err = rawWriter.Write([]string{"round", "execution_order", "n_attr", "total_ms", "key_generation_ms", "group_signature_ms", "expiry_commitment_ms", "credential_signing_ms", "credential_verification_ms"}); err != nil {
		panic(err)
	}

	var seedBytes [8]byte
	if _, err = crand.Read(seedBytes[:]); err != nil {
		panic(err)
	}
	rng := mathrand.New(mathrand.NewSource(int64(binary.LittleEndian.Uint64(seedBytes[:]))))
	timingsByAttr := make(map[int][]float64, len(attributeCounts))
	var finalSample *PrescriptionPackage
	for round := 1; round <= runs; round++ {
		order := append([]int(nil), attributeCounts...)
		rng.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
		for position, nAttr := range order {
			timing, sample, runErr := runIssuanceExperiment(nAttr, groupPublicKey, hpMemberKey)
			if runErr != nil {
				panic(runErr)
			}
			timingsByAttr[nAttr] = append(timingsByAttr[nAttr], timing.TotalMS)
			if err = rawWriter.Write([]string{strconv.Itoa(round), strconv.Itoa(position + 1), strconv.Itoa(nAttr), fmt.Sprintf("%.6f", timing.TotalMS), fmt.Sprintf("%.6f", timing.KeyGenerationMS), fmt.Sprintf("%.6f", timing.GroupSignatureMS), fmt.Sprintf("%.6f", timing.ExpiryCommitmentMS), fmt.Sprintf("%.6f", timing.CredentialSigningMS), fmt.Sprintf("%.6f", timing.CredentialVerificationMS)}); err != nil {
				panic(err)
			}
			if nAttr == attributeCounts[len(attributeCounts)-1] {
				finalSample = sample
			}
		}
	}

	fmt.Printf("%-8s %-12s %-12s %-10s %-12s %-12s\n", "N_attr", "Mean (ms)", "SD (ms)", "CV (%)", "Median (ms)", "IQR (ms)")
	for _, nAttr := range attributeCounts {
		summary := summarize(timingsByAttr[nAttr])
		if err = writer.Write([]string{
			strconv.Itoa(nAttr),
			strconv.Itoa(runs),
			fmt.Sprintf("%.3f", summary.MeanMS),
			fmt.Sprintf("%.3f", summary.SDMS),
			fmt.Sprintf("%.3f", summary.CV),
			fmt.Sprintf("%.3f", summary.MedianMS),
			fmt.Sprintf("%.3f", summary.IQRMS),
			strconv.Itoa(bbs04.SignatureSize()),
			strconv.Itoa(runtime.GOMAXPROCS(0)),
		}); err != nil {
			panic(err)
		}
		fmt.Printf("%-8d %-12.3f %-12.3f %-10.3f %-12.3f %-12.3f\n", nAttr, summary.MeanMS, summary.SDMS, summary.CV, summary.MedianMS, summary.IQRMS)
	}

	writer.Flush()
	if err = writer.Error(); err != nil {
		panic(err)
	}
	rawWriter.Flush()
	if err = rawWriter.Error(); err != nil {
		panic(err)
	}
	if finalSample == nil {
		panic("no sample prescription package generated")
	}
	if err = writeSamplePackage(finalSample); err != nil {
		panic(err)
	}

	fmt.Printf("\nBBS group-signature preflight passed.\n")
	fmt.Printf("Serialized BBS group-signature size: %d bytes.\n", bbs04.SignatureSize())
	fmt.Printf("Warm-up: %d untimed executions per configuration.\n", warmupRuns)
	fmt.Printf("Measurement order: randomized and interleaved by round.\n")
	fmt.Printf("Summary: %s\nRaw/component timings: %s\nSample package: %s\n", resultsCSV, rawResultsCSV, samplePackageJSON)
}
