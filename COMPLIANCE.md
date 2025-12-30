# Compliance Mapping: NIST CSF & ISO 27001

This tool automates the validation of controls required by vital cybersecurity frameworks. Note the following mappings.

## 1. NIST Cybersecurity Framework (CSF) 2.0 Mapping
| Function | NIST Category | NIST Control | Description |
| :--- | :--- | :--- | :--- |
| `audit_tls()` | **Protect (PR.DS)** | PR.DS-01 | Data-in-transit is protected by encryption. |
| `scsv_downgrade_audit()` | **Protect (PR.PS)** | PR.PS-01 | Configuration management: Disabling insecure protocols. |
| `hsts_check()` | **Protect (PR.DS)** | PR.DS-02 | Maintaining data integrity during transfer. |
| `check_dns_security()` | **Identify (ID.GV)** | ID.GV-01 | Ensuring only authorized CAs can issue certificates. |
| `check_mta_sts()` | **Protect (PR.IR)** | PR.IR-02 | Protecting communication resiliently. |

## 2. ISO/IEC 27001:2022 Mapping
| Control ID | Title | Script Validation |
| :--- | :--- | :--- |
| **A.8.24** | Use of Cryptography | Validates cipher strength (AES-256) and Perfect Forward Secrecy(PFS). |
| **A.8.20** | Network Security | Tests for protocol downgrade vulnerabilities. |
| **A.5.31** | Legal/Regulatory | Supports privacy mandates by checking MTA-STS. |
| **A.8.21** | Security of Network Services | Audits CAA records for infrastructure trust. |



## 3. Privacy Engineering Significance
By validating **Perfect Forward Secrecy (PFS)** and **MTA-STS**, this tool directly supports **GDPR Article 32** (Security of Processing), ensuring that personal data is not only encrypted but protected against future decryption if keys are compromised.
