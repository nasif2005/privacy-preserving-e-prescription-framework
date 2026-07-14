package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	bbs04 "eprx-bbs04"
)

type summary struct{ mean, sd, cv float64 }

const setupBatch = 100

func warmup() error {
	for i := 0; i < 100; i++ {
		gpk, gmk, err := bbs04.Setup()
		if err != nil {
			return err
		}
		for j := 0; j < 100; j++ {
			if _, err := bbs04.IssueMemberKey(gpk, gmk); err != nil {
				return err
			}
		}
	}
	return nil
}

func stats(ns []int64) summary {
	var sum float64
	for _, n := range ns {
		sum += float64(n)
	}
	mean := sum / float64(len(ns))
	var squares float64
	for _, n := range ns {
		d := float64(n) - mean
		squares += d * d
	}
	sd := 0.0
	if len(ns) > 1 {
		sd = math.Sqrt(squares / float64(len(ns)-1))
	}
	cv := 0.0
	if mean != 0 {
		cv = 100 * sd / mean
	}
	return summary{mean, sd, cv}
}

func parseSizes(value string) ([]int, error) {
	parts := strings.Split(value, ",")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, e := strconv.Atoi(strings.TrimSpace(p))
		if e != nil || n < 1 {
			return nil, fmt.Errorf("invalid workload %q", p)
		}
		out = append(out, n)
	}
	return out, nil
}

func preflight() error {
	gpk, gmk, e := bbs04.Setup()
	if e != nil {
		return e
	}
	member, e := bbs04.IssueMemberKey(gpk, gmk)
	if e != nil {
		return e
	}
	message := []byte("HP authentication preflight")
	sig, e := bbs04.Sign(gpk, member, message)
	if e != nil {
		return e
	}
	if !bbs04.Verify(gpk, message, sig) {
		return fmt.Errorf("valid signature rejected")
	}
	opened, e := bbs04.Open(gmk, sig)
	if e != nil {
		return e
	}
	registry := map[string]string{bbs04.CertificateID(&member.A): "HP-PREFLIGHT"}
	if registry[bbs04.CertificateID(&opened)] != "HP-PREFLIGHT" {
		return fmt.Errorf("opening/registry lookup failed")
	}
	return nil
}

func main() {
	runtime.GOMAXPROCS(1)
	readings := flag.Int("readings", 100, "independent readings per configuration")
	sizesText := flag.String("sizes", "10,100,1000,10000", "comma-separated HP workloads")
	out := flag.String("out", "5.2.1_hp_enrollment_results.csv", "CSV output path")
	flag.Parse()
	if *readings < 2 {
		fmt.Fprintln(os.Stderr, "readings must be at least 2")
		os.Exit(2)
	}
	sizes, e := parseSizes(*sizesText)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
	if e = preflight(); e != nil {
		fmt.Fprintln(os.Stderr, "cryptographic preflight failed:", e)
		os.Exit(1)
	}
	if e = warmup(); e != nil {
		fmt.Fprintln(os.Stderr, "cryptographic warm-up failed:", e)
		os.Exit(1)
	}

	f, e := os.Create(*out)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	w.Write([]string{"operation", "n_hp", "readings", "mean_ns", "stddev_ns", "cv_percent", "mean_per_hp_ns", "gpk_bytes", "gmk_bytes", "member_key_bytes", "signature_bytes", "gomaxprocs", "operations_per_sample"})

	setupSamples := make([]int64, *readings)
	for r := range setupSamples {
		start := time.Now()
		for i := 0; i < setupBatch; i++ {
			if _, _, e = bbs04.Setup(); e != nil {
				panic(e)
			}
		}
		setupSamples[r] = time.Since(start).Nanoseconds() / setupBatch
	}
	ss := stats(setupSamples)
	w.Write([]string{"group_setup", "0", strconv.Itoa(*readings), fmt.Sprintf("%.3f", ss.mean), fmt.Sprintf("%.3f", ss.sd), fmt.Sprintf("%.6f", ss.cv), "0", strconv.Itoa(bbs04.PublicKeySize()), strconv.Itoa(bbs04.ManagerKeySize()), strconv.Itoa(bbs04.MemberKeySize()), strconv.Itoa(bbs04.SignatureSize()), "1", strconv.Itoa(setupBatch)})
	fmt.Printf("%-18s %8s %14s %14s %10s %14s\n", "Operation", "N_HP", "Mean (ms)", "SD (ms)", "CV (%)", "Per HP (us)")
	fmt.Printf("%-18s %8d %14.3f %14.3f %10.3f %14s\n", "Group setup", 0, ss.mean/1e6, ss.sd/1e6, ss.cv, "-")

	for _, n := range sizes {
		samples := make([]int64, *readings)
		repetitions := 1
		if n < 1000 {
			repetitions = (1000 + n - 1) / n
		}
		for r := 0; r < *readings; r++ {
			gpk, gmk, e := bbs04.Setup()
			if e != nil {
				panic(e)
			}
			start := time.Now()
			for repeat := 0; repeat < repetitions; repeat++ {
				for i := 0; i < n; i++ {
					if _, e = bbs04.IssueMemberKey(gpk, gmk); e != nil {
						panic(e)
					}
				}
			}
			samples[r] = time.Since(start).Nanoseconds() / int64(repetitions)
		}
		s := stats(samples)
		per := s.mean / float64(n)
		w.Write([]string{"member_key_issuance", strconv.Itoa(n), strconv.Itoa(*readings), fmt.Sprintf("%.3f", s.mean), fmt.Sprintf("%.3f", s.sd), fmt.Sprintf("%.6f", s.cv), fmt.Sprintf("%.3f", per), strconv.Itoa(bbs04.PublicKeySize()), strconv.Itoa(bbs04.ManagerKeySize()), strconv.Itoa(bbs04.MemberKeySize()), strconv.Itoa(bbs04.SignatureSize()), "1", strconv.Itoa(n * repetitions)})
		fmt.Printf("%-18s %8d %14.3f %14.3f %10.3f %14.3f\n", "Member issuance", n, s.mean/1e6, s.sd/1e6, s.cv, per/1e3)
	}
	w.Flush()
	if e = w.Error(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	fmt.Printf("\nPreflight: Sign, Verify, Open, and registry lookup passed.\nWarm-up: 100 setups and 10,000 member issuances (untimed).\nExecution: sequential, runtime.GOMAXPROCS(1); setup batch=%d.\nSizes: GPK=%d B, GMK=%d B, member key=%d B, signature=%d B.\nCSV: %s\n", setupBatch, bbs04.PublicKeySize(), bbs04.ManagerKeySize(), bbs04.MemberKeySize(), bbs04.SignatureSize(), *out)
}
