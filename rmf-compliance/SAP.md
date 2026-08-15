# Security Assessment Plan (SAP)

**System Name:** T-Pot O&G Threat Intelligence Honeypot Lab (TPOT-HIVE-LAB)
**Prepared By:** Marcus
**Date:** August 12, 2026
**Related Document:** System Security Plan (SSP), dated August 12, 2026
**Assessment Baseline:** NIST SP 800-53 Rev. 5, Moderate; assessment procedures aligned to NIST SP 800-53A

---

## 1. Purpose and Scope

This SAP defines the methodology, scope, roles, schedule, and rules of engagement for assessing the security controls implemented in the T-Pot honeypot lab, as documented in the SSP. The assessment determines whether implemented controls are operating as intended and identifies gaps for POA&M tracking.

**In Scope:**
- Host OS hardening (Ubuntu 22.04 VM: `<vm-name>`)
- Network boundary controls (NSG rules, subnet segmentation)
- Identity/access controls (SSH configuration, authentication)
- Encryption at rest (Azure Disk Encryption)
- Monitoring/logging configuration (Defender for Cloud, Log Analytics, ELK, fail2ban)
- Vulnerability posture of the underlying OS and exposed services

**Out of Scope:**
- Azure physical infrastructure and hypervisor (covered by Microsoft's own compliance attestations, not independently assessed here)
- Intentionally-exposed honeypot service ports (these are assessed for *correct exposure per design*, not treated as findings — an open Modbus port on Conpot is expected behavior, not a vulnerability)
- Any system outside the `<resource-group>` resource group

---

## 2. Assessment Team and Roles

| Role | Assigned To |
|---|---|
| Assessor / Security Control Assessor (SCA) | Marcus |
| System Owner (assessed party) | Marcus |
| Assessment reviewed by | Self-review (lab context); designed to mirror AO/SCA separation of duties conceptually |

*Note: In a lab/portfolio context the assessor and system owner are the same individual. In a production RMF engagement, these roles would be independent per NIST SP 800-37 separation-of-duties guidance — noted here to demonstrate awareness of that requirement.*

---

## 3. Assessment Methodology

Assessment follows a hybrid of automated scanning and manual/configuration review, consistent with NIST SP 800-53A assessment methods: **Examine, Interview, Test**.

| Method | Application |
|---|---|
| Examine | Review of sshd_config, sysctl hardening file, NSG rule set, Key Vault encryption status, fail2ban jail configuration, logrotate policy |
| Test | Automated compliance scan (OpenSCAP), authenticated vulnerability scan (Nessus) |
| Interview | N/A (single-operator lab; self-documentation substitutes for interview artifacts) |

### 3.1 Tools Used

| Tool | Purpose | Status |
|---|---|---|
| OpenSCAP (CIS Ubuntu Linux 22.04 Benchmark, Level 2) | Configuration compliance audit against CIS baseline | **Complete** |
| Tenable Nessus (credentialed scan) | Authenticated vulnerability scan of host OS and services | **Complete** |
| Elasticvue / Kibana | Review of honeypot telemetry integrity and dashboard function | Planned |
| Manual NSG/config review | Validate boundary and access controls match SSP as-built | Complete (informs SSP Section 3) |

---

## 4. Assessment Procedures by Control Family

| Control Family | Procedure |
|---|---|
| AC (Access Control) | Examine NSG rule set for correct source-IP restriction on management ports; verify no password auth accepted via `sshd -T` output |
| IA (Identification & Authentication) | Examine sshd_config for `PubkeyAuthentication yes`, `PasswordAuthentication no`; confirm key-only login in practice |
| SC (System & Comms Protection) | Examine Key Vault encryption status on VM disks (Azure Portal → VM → Disks → Encryption); verify TLS cert presence on NGINX (port 64296/64297) |
| SI (System & Information Integrity) | Test via OpenSCAP CIS scan; test via Nessus credentialed scan; examine unattended-upgrades configuration and fail2ban jail status (`fail2ban-client status sshd-tpot`) |
| AU (Audit & Accountability) | Examine logrotate configuration; examine Kibana for functioning ingestion pipelines across honeypot sensors |
| CM (Configuration Management) | Examine sysctl hardening file against documented baseline in SSP Section 3.6 |
| RA (Risk Assessment) | Test via OpenSCAP + Nessus (this constitutes the RA-5 control test itself) |

---

## 5. Schedule

| Activity | Status |
|---|---|
| 1. OpenSCAP CIS Level 2 Audit | ✅ Complete |
| 2. Nessus Credentialed Scan | ✅ Complete |
| 3. MITRE ATT&CK Mapping of captured attack data | ⬜ Planned |
| 4. Manual control examination (NSG, sshd, Key Vault, fail2ban) | ✅ Complete (folded into SAR) |
| 5. SAR finalization and POA&M generation | ✅ This document set |

---

## 6. Rules of Engagement

- Assessment activities are performed against the assessor's own lab system; no third-party authorization required.
- Vulnerability scanning (Nessus) is authenticated/credentialed and performed only against `<vm-name>` within `<resource-group>` — no scanning of Azure platform services or other tenants.
- No assessment activity targets the intentionally-open honeypot ports as if they were unintended exposures; those are validated against the SSP's documented design intent instead.
- Findings are documented regardless of severity; no results are suppressed.

---

*Results of this assessment are documented in the accompanying Security Assessment Report (SAR).*
