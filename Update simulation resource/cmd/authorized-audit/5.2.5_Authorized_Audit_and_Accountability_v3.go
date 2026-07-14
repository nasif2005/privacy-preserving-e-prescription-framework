// Section 5.2.5: Authorized Audit and Accountability
//
// Measures genuine BBS group-signature opening and membership-registry lookup.
// The audit-authority material is local research data and must not be exposed
// to pharmacies or included in prescription presentations.
package main

import (
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"runtime"
	"sort"
	"strconv"
	"time"

	bbs04 "eprx-bbs04"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	timingRuns       = 100
	operationsPerRun = 100
	warmupOperations = 100
	authDomain       = "EPRX-AUTH-PRES-v1"
	groupKeyFile     = "bbs_group_public_key.json"
	auditKeyFile     = "bbs_audit_authority.json"
	presentationFile = "presentation_payload_1.json"
	resultsFile      = "5.2.5_authorized_audit_results.csv"
	reportFile       = "audit_report.json"
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
}

type AuditMemberRecord struct {
	HPID              string `json:"hp_id"`
	LicenseNo         string `json:"license_no"`
	Organization      string `json:"organization"`
	MemberCertificate string `json:"member_certificate_a"`
}

type SerializedAuditAuthority struct {
	Xi1     string              `json:"xi_1"`
	Xi2     string              `json:"xi_2"`
	Gamma   string              `json:"gamma"`
	Members []AuditMemberRecord `json:"members"`
}

type AuditReport struct {
	Status       string `json:"status"`
	RecoveredHP  string `json:"recovered_hp"`
	LicenseNo    string `json:"license_no"`
	Organization string `json:"organization"`
	IssueTime    int64  `json:"issue_time"`
	Reason       string `json:"reason"`
}

type Summary struct {
	Mean   float64
	SD     float64
	CV     float64
	Median float64
	IQR    float64
}

func decodeHex(value, label string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("cannot decode %s: %w", label, err)
	}
	return decoded, nil
}

func decodeG1(value, label string) (bls.G1Affine, error) {
	var point bls.G1Affine
	encoded, err := decodeHex(value, label)
	if err != nil {
		return point, err
	}
	if _, err = point.SetBytes(encoded); err != nil {
		return point, fmt.Errorf("cannot decode %s: %w", label, err)
	}
	if !point.IsOnCurve() || !point.IsInSubGroup() {
		return point, fmt.Errorf("%s is not a valid G1 subgroup point", label)
	}
	return point, nil
}

func decodeG2(value, label string) (bls.G2Affine, error) {
	var point bls.G2Affine
	encoded, err := decodeHex(value, label)
	if err != nil {
		return point, err
	}
	if _, err = point.SetBytes(encoded); err != nil {
		return point, fmt.Errorf("cannot decode %s: %w", label, err)
	}
	if !point.IsOnCurve() || !point.IsInSubGroup() {
		return point, fmt.Errorf("%s is not a valid G2 subgroup point", label)
	}
	return point, nil
}

func decodeScalar(value, label string) (fr.Element, error) {
	var scalar fr.Element
	encoded, err := decodeHex(value, label)
	if err != nil {
		return scalar, err
	}
	if len(encoded) != fr.Bytes {
		return scalar, fmt.Errorf("%s must contain %d bytes", label, fr.Bytes)
	}
	if err = scalar.SetBytesCanonical(encoded); err != nil {
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

func loadAuditAuthority() (
	*bbs04.GroupManagerKey,
	map[string]AuditMemberRecord,
	error,
) {
	encoded, err := os.ReadFile(auditKeyFile)
	if err != nil {
		return nil, nil, err
	}
	var serialized SerializedAuditAuthority
	if err = json.Unmarshal(encoded, &serialized); err != nil {
		return nil, nil, err
	}
	xi1, err := decodeScalar(serialized.Xi1, "opening key xi1")
	if err != nil {
		return nil, nil, err
	}
	xi2, err := decodeScalar(serialized.Xi2, "opening key xi2")
	if err != nil {
		return nil, nil, err
	}
	gamma, err := decodeScalar(serialized.Gamma, "manager key gamma")
	if err != nil {
		return nil, nil, err
	}

	registry := make(map[string]AuditMemberRecord, len(serialized.Members))
	for _, member := range serialized.Members {
		certificate, decodeErr := decodeG1(member.MemberCertificate, "member certificate")
		if decodeErr != nil {
			return nil, nil, decodeErr
		}
		registry[bbs04.CertificateID(&certificate)] = member
	}
	return &bbs04.GroupManagerKey{Xi1: xi1, Xi2: xi2, Gamma: gamma}, registry, nil
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

func loadPresentation() (*PresentationPayload, error) {
	encoded, err := os.ReadFile(presentationFile)
	if err != nil {
		return nil, err
	}
	var payload PresentationPayload
	if err = json.Unmarshal(encoded, &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

// runAudit performs genuine manager-controlled opening, membership-registry
// lookup, and audit-report construction. Signature verification is performed
// once during preflight because the input is a previously verified pharmacy
// presentation.
func runAudit(
	managerKey *bbs04.GroupManagerKey,
	registry map[string]AuditMemberRecord,
	signature *bbs04.GroupSignature,
	issueTime int64,
) (AuditReport, error) {
	openedCertificate, err := bbs04.Open(managerKey, signature)
	if err != nil {
		return AuditReport{}, err
	}
	member, found := registry[bbs04.CertificateID(&openedCertificate)]
	if !found {
		return AuditReport{}, fmt.Errorf("opened member certificate is absent from registry")
	}
	return AuditReport{
		Status:       "Recovered",
		RecoveredHP:  member.HPID,
		LicenseNo:    member.LicenseNo,
		Organization: member.Organization,
		IssueTime:    issueTime,
		Reason:       "Authorized audit request",
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
	return Summary{
		Mean: mean, SD: sd, CV: 100 * sd / mean,
		Median: median(ordered), IQR: q3 - q1,
	}
}

func main() {
	runtime.GOMAXPROCS(1)
	groupPublicKey, err := loadGroupPublicKey()
	if err != nil {
		log.Fatal("cannot load group public key:", err)
	}
	managerKey, registry, err := loadAuditAuthority()
	if err != nil {
		log.Fatal("cannot load audit-authority material:", err)
	}
	payload, err := loadPresentation()
	if err != nil {
		log.Fatal("cannot load presentation:", err)
	}
	signature, err := decodeGroupSignature(payload.AuthorizationCertificate.SigmaGrp)
	if err != nil {
		log.Fatal(err)
	}
	issuerPublicKey, err := decodeHex(
		payload.AuthorizationCertificate.EphemeralIssuerPK,
		"ephemeral issuer public key",
	)
	if err != nil {
		log.Fatal(err)
	}
	authMessage := authorizationMessage(
		issuerPublicKey,
		payload.AuthorizationCertificate.IssueTime,
	)
	if !bbs04.Verify(groupPublicKey, authMessage, signature) {
		log.Fatal("authorization signature failed preflight verification")
	}

	for operation := 0; operation < warmupOperations; operation++ {
		if _, err = runAudit(
			managerKey, registry, signature,
			payload.AuthorizationCertificate.IssueTime,
		); err != nil {
			log.Fatal(err)
		}
	}

	// Each sample is the normalized per-audit latency from a batch of genuine
	// cryptographic opening operations. Batching reduces timer-resolution noise.
	samples := make([]float64, 0, timingRuns)
	for run := 0; run < timingRuns; run++ {
		start := time.Now()
		for operation := 0; operation < operationsPerRun; operation++ {
			if _, err = runAudit(
				managerKey, registry, signature,
				payload.AuthorizationCertificate.IssueTime,
			); err != nil {
				log.Fatal(err)
			}
		}
		elapsedPerAuditMS := float64(time.Since(start).Nanoseconds()) /
			1e6 / float64(operationsPerRun)
		samples = append(samples, elapsedPerAuditMS)
	}

	summary := summarize(samples)
	report, err := runAudit(
		managerKey, registry, signature,
		payload.AuthorizationCertificate.IssueTime,
	)
	if err != nil {
		log.Fatal(err)
	}
	reportBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	if err = os.WriteFile(reportFile, reportBytes, 0o644); err != nil {
		log.Fatal(err)
	}

	file, err := os.Create(resultsFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	writer.Write([]string{
		"timing_runs", "operations_per_run", "mean_ms", "stddev_ms",
		"cv_percent", "median_ms", "iqr_ms", "gomaxprocs",
	})
	writer.Write([]string{
		strconv.Itoa(timingRuns), strconv.Itoa(operationsPerRun),
		fmt.Sprintf("%.6f", summary.Mean), fmt.Sprintf("%.6f", summary.SD),
		fmt.Sprintf("%.3f", summary.CV), fmt.Sprintf("%.6f", summary.Median),
		fmt.Sprintf("%.6f", summary.IQR), strconv.Itoa(runtime.GOMAXPROCS(0)),
	})
	writer.Flush()
	if err = writer.Error(); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Authorized audit recovered %s (%s).\n", report.RecoveredHP, report.LicenseNo)
	fmt.Printf("Mean opening-and-lookup latency: %.6f ms.\n", summary.Mean)
	fmt.Printf("SD: %.6f ms; CV: %.3f%%; median: %.6f ms; IQR: %.6f ms.\n",
		summary.SD, summary.CV, summary.Median, summary.IQR)
	fmt.Printf("Results: %s\nAudit report: %s\n", resultsFile, reportFile)
}
