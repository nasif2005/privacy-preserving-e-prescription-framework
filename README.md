# Privacy-Preserving E-Prescription Framework

This repository provides the reference implementation, simulation artifacts, and formal models supporting the paper:

> **“A Privacy-Preserving Framework for Electronic Prescription Verification”**

---

## 📌 Overview

Electronic prescription systems must verify prescription legitimacy, patient ownership, and compliance with validity constraints during medication dispensing. At the same time, prescription records contain sensitive medical information.

This project implements a **privacy-preserving prescription verification framework** designed to:

* reduce unnecessary disclosure of prescription data
* limit cross-transaction linkability of patients and prescribers
* support accountability under authorized audit conditions
* enable verification of policy constraints over hidden attributes

The framework integrates:

* anonymous prescriber authorization (group signatures)
* selective disclosure of prescription attributes (credential-based)
* unified zero-knowledge proofs for validity checking

---

## 🧱 Repository Structure

```
privacy-preserving-e-prescription-framework/
│
├── Simulation code/
│   ├── scyther code/                # Scyther protocol models
│   ├── tamarin code/                # Tamarin formal models
│   ├── bbs04_python_core.py         # Group signature primitives
│   ├── cl_bilinear_core.py          # CL signature primitives
│   ├── cl_bilinear_pok.py           # Selective disclosure proof
│   ├── cl_bilinear_pok_range.py     # Range proof (expiry validation)
│   ├── Issuance of Prescription Credential.py
│   ├── Patient Proof-of-Knowledge Generation for the Prescription.py
│   ├── Verification of the Proof-of-Knowledge of the Prescription.py
│   ├── issuance of doctor's group key.py
│   ├── accountability cost.py
│   └── command.txt                  # Execution notes
│
├── Simulation Measurement/
│   ├── *.csv                        # Raw simulation outputs
│   ├── *.png / *.pdf                # Generated plots
│   └── matlab code.txt              # Plot generation scripts
│
└── README.md
```

---

## ⚙️ Simulation Components

The simulation models the core cryptographic operations of the framework:

* Healthcare professional enrollment
* Prescription credential issuance
* Patient proof generation
* Pharmacy proof verification
* Accountability (signature opening)

The evaluation focuses on **computational cost under synthetic workloads**, excluding network and system integration overhead.

---

## 🔐 Formal Verification

This repository includes symbolic models for protocol analysis:

### Scyther Models

* Analyze secrecy and replay-related properties
* Model prescription presentation and verification flow

### Tamarin Models

* Analyze privacy properties such as:

  * prescriber indistinguishability
  * patient unlinkability
  * conditional traceability

These models operate under an abstract symbolic setting and complement the system-level analysis presented in the paper.

---

## ▶️ How to Run (Simulation)

Example workflow:

```bash
python "Issuance of Prescription Credential.py"
python "Patient Proof-of-Knowledge Generation for the Prescription.py"
python "Verification of the Proof-of-Knowledge of the Prescription.py"
```

Additional commands and experiment configurations are provided in:

```
Simulation code/command.txt
```

---

## 📊 Results

The `Simulation Measurement/` directory contains:

* Raw data (`.csv`)
* Visualization outputs (`.png`, `.pdf`)
* Plot generation scripts

These results correspond to the evaluation presented in the paper, including:

* enrollment cost vs group size
* credential issuance latency
* proof generation and verification cost
* accountability (opening) overhead

---

## ⚠️ Scope and Assumptions

This implementation is intended for **research and evaluation purposes**.

* Results are based on **simulation of cryptographic operations**
* Network, storage, and real-world deployment factors are not included
* Formal models are **symbolic abstractions**, not computational proofs
* The system assumes a trusted authority (APC) for enrollment and audit

---

## 📄 Reproducibility

All artifacts required to reproduce the reported evaluation are included:

* simulation scripts
* datasets and outputs
* plotting resources
* formal verification models

---

## 📜 License

[Add your license here — e.g., MIT, Apache 2.0]

---

## 👤 Author

Nasif M.
(Research on privacy-preserving systems and healthcare security)



---
