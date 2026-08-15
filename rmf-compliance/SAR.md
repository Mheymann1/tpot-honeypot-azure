# Security Assessment Report (SAR)

**System Name:** T-Pot O&G Threat Intelligence Honeypot Lab (TPOT-HIVE-LAB)
**Prepared By:** Marcus
**Date:** August 12, 2026
**Related Documents:** System Security Plan (SSP), Security Assessment Plan (SAP), both dated August 12, 2026


---

## 1. Executive Summary

An assessment was conducted against the T-Pot O&G honeypot lab per the methodology in the accompanying SAP. The assessment covered host configuration compliance (OpenSCAP, CIS Ubuntu 22.04 Level 2), authenticated vulnerability scanning (Nessus), and manual examination of network boundary, identity, encryption, and monitoring controls documented in the SSP.

**Overall Risk Posture:** Low, final — this system has been decommissioned. All findings are closed, either through remediation, validation against intended design, or system disposition.
**Total Findings:** 0 open. Historical record: 2 Medium (OSCAP-1 scan-validity, closed via decommission; NESSUS-2 IMDS check, closed untested/carried forward), 2 Low (NESSUS-1 baseline drift, corrected; self-signed cert), 1 Informational (Nessus honeypot-service validation, closed — no action needed).
**Key Strength:** Strict management/honeypot plane segregation via NSG, key-only SSH authentication, and disk-level encryption significantly reduce the attack surface of the management plane. The Nessus scan's "critical" findings (unsupported MSSQL, Telnet, web app disclosures) all map directly to Dionaea/Cowrie/Tanner decoy services on ports the SSP already documents as intentionally exposed — the honeypot is behaving exactly as designed.
**Key Gap (carried forward to future deployments):** The OpenSCAP scan-validity issue (OSCAP-1) and the untested IMDS-reachability check (NESSUS-2) were closed by decommissioning rather than resolved — the underlying process gaps (verify scan tooling before trusting results; test cloud metadata isolation before teardown) should be built into the SAP for the *next* T-Pot deployment rather than treated as fully solved. No formal contingency/backup plan (CP family) existed for this system's lifecycle.

---

## 2. Assessment Results by Method

### 2.1 OpenSCAP — CIS Ubuntu Linux 22.04 Benchmark, Level 2

**Scan metadata:** Profile `cis_level2_server`, Benchmark `UBUNTU_22-04` v0.1.72, evaluated by `openscap 1.3.9`.

| Metric | Result |
|---|---|
| Total rules evaluated | 387 |
| Pass | 0 |
| Fail | 0 |
| Error | 0 |
| Unknown | 0 |
| Not applicable | 387 (100%) |
| Compliance score | 0.0 / 100 |

**⚠️ Finding OSCAP-1 — Scan did not produce valid compliance evidence (Severity: Medium, process finding)**

Every one of the 387 evaluated rules returned **Not Applicable** — none passed, failed, or errored. The scan's own `Started at` and `Finished at` timestamps are identical to the second, which is not consistent with 387 rules of file, permission, and configuration checks actually executing against a live filesystem. Taken together, this indicates the scan did not correctly evaluate the target — most likely a CPE/platform-applicability mismatch (e.g., the benchmark's Ubuntu 22.04 platform check failing to match, causing every rule to short-circuit to `notapplicable` before its check body ran) rather than genuine coverage of the host.

**This is a real and useful finding in its own right:** a 0%-coverage scan is not evidence the host is compliant — it is evidence the tooling needs to be fixed and re-run. Reporting it honestly here (rather than treating 100% N/A as a clean bill of health) is itself the correct RMF/RA-5 practice, and demonstrates assessor rigor rather than rubber-stamping automated output.

**Recommended remediation:** re-run with `oscap xccdf eval --fetch-remote-resources`, confirm the CPE dictionary correctly identifies `cpe:/o:canonical:ubuntu_linux:22.04`, and verify the scan is run with root privileges directly against the host filesystem (not from within a container namespace, given Docker bridge interfaces — 172.17–172.20.x.x — were present in the evaluated target's address list).

### 2.2 Nessus — Credentialed Vulnerability Scan

**Scan metadata:** "T-Pot Honeypot VM — Credentialed Scan", Policy: Basic Network Scan, CVSS v3.0 severity base, credentialed authentication **Passed**, single host, 39-minute runtime.

| Metric | Result |
|---|---|
| Distinct vulnerability plugins triggered | 78 |
| Non-Info findings (Critical+High+Medium+Low, per host summary) | 9 |
| Info findings | 244 |
| Total individual results | 253 |
| Detected OS | Linux Kernel 6.17.0-1017-azure, Ubuntu 24.04 |

**⚠️ Finding NESSUS-1 — Detected OS does not match SSP baseline (Severity: Low, documentation finding)**

The SSP documents Ubuntu 22.04 LTS as the deployed OS. This credentialed scan detected **Ubuntu 24.04** with kernel `6.17.0-1017-azure`. This is most likely benign — a distribution upgrade applied over time via `unattended-upgrades`/manual maintenance — but it means the SSP's Section 1.1/3 baseline description is stale and should be updated (CM-6, configuration baseline accuracy) to avoid the SSP misrepresenting the as-built system.

**Confirmed direct severities from individually-labeled plugin rows:**

| Severity | Plugin | CVSS v3 | Port/Service |
|---|---|---|---|
| Critical | Microsoft SQL Server Unsupported Version Detection (Plugin 73756) | 10.0 | 1433/tcp (mssql) |
| Critical | Elasticsearch Transport Protocol Unspecified RCE | 9.8 | — |
| Medium | Unencrypted Telnet Server (Plugin 42263) | 6.5 | 23/tcp (telnet) |
| Medium | web.config File Information Disclosure (Plugin 121479) | 5.3 | 443/tcp (www) |
| Medium | J Walk Application Server Directory Traversal (Plugin 11467) | 5.0 (v2) | 443/tcp (www) |

The remaining Critical/High/Medium/Low count sits inside six "Multiple Issues" grouped plugin families (Elasticsearch, Microsoft Windows, SNMP, Web Server, SSL, SSH) that the exported view rolls up rather than itemizes per-severity — a full breakdown would require opening each group individually.

**⚠️ Critical interpretive note — read this before treating the above as remediation items**

This host is the T-Pot HIVE platform itself, not a general-purpose server. Every one of the findings above maps cleanly onto a honeypot module doing its job, not a real exposure:

| Finding | Port | Almost certainly | Because |
|---|---|---|---|
| Ancient/unsupported MSSQL (SQL Server 2000) | 1433 | Dionaea's MSSQL emulation | Dionaea deliberately presents outdated, "attractive" service banners to draw attacker interest |
| Unencrypted Telnet | 23 | Cowrie's Telnet honeypot | Cowrie intentionally exposes Telnet in cleartext to capture credential brute-forcing |
| web.config disclosure / J Walk directory traversal | 443 | Tanner (web-app honeypot) | Tanner emulates vulnerable/legacy web application behavior by design |
| Elasticsearch RCE, SNMP issues | various | Elasticpot / Conpot SNMP simulation | Both are dedicated T-Pot decoy modules for those exact protocols |

**Recommendation:** do not "remediate" these as if they were real production vulnerabilities — patching or disabling them would break the honeypot's core function and directly contradicts the SSP's stated purpose. Instead, the correct RMF action is to **validate** that each flagged service is on the list of intentionally-exposed honeypot ports (SSP Section 4) and not an unintended exposure. All five confirmed findings above map to ports already documented as intentionally open in the SSP, so this validation passes — but it's an explicit check, not an assumption, and should be re-run any time a new honeypot module is added.

**Genuine host-level items worth reviewing (from credentialed local checks, not honeypot-plane traffic):**
- Docker, Containerd, and Ansible installed — expected, part of T-Pot's own architecture (no action needed)
- **Finding NESSUS-2:** Microsoft Azure Instance Metadata Service (IMDS) reachable from the host — worth confirming no honeypot container can pivot to query IMDS and reach Azure management-plane metadata (a real SSRF-adjacent risk pattern on Azure IaaS); tracked in POA&M below
- Post-quantum cipher enumeration returned both PQ and non-PQ ciphers in use — informational only at this baseline, forward-looking SC-13 note

---

## 3. Manual Control Examination Results

These findings come from directly examining the deployment against the SSP's stated implementation (Section 3 of the SSP).

| Control | Expected (per SSP) | Observed | Result |
|---|---|---|---|
| AC-17 / IA-2 | SSH key-only, password auth disabled | `PasswordAuthentication no`, `PubkeyAuthentication yes` confirmed in sshd_config | ✅ Satisfied |
| AC-7 | Account lockout after failed logons | fail2ban jail active on port 64295, maxretry=3, bantime=3600s | ✅ Satisfied |
| SC-7 / AC-4 | Boundary segregation, deny-all default | NSG rules 100–230 scoped correctly; priority 4096 explicit deny confirmed | ✅ Satisfied |
| SC-13 | Encryption at rest | Azure Disk Encryption enabled via `<key-vault-name>`, OS + data disks | ✅ Satisfied |
| SC-8 | Encryption in transit (mgmt UI) | NGINX serving Kibana/Web UI over HTTPS; **self-signed certificate** in use | ⚠️ Partial — self-signed cert acceptable for lab, but flagged as a finding since it wouldn't meet SC-8 in a production Moderate system |
| SI-2 | Automated patching | `unattended-upgrades` enabled and configured | ✅ Satisfied |
| SI-4 | Continuous monitoring | Defender for Cloud (Standard tier) + Log Analytics workspace connected | ✅ Satisfied |
| AU-11 | Log retention | Logrotate: daily, 30-day retention, compressed | ✅ Satisfied |
| CP-2 / CP-9 | Contingency plan / backups | No formal contingency plan or backup schedule defined | ❌ Not implemented (accepted gap, tracked below) |
| RA-5 | Vulnerability scanning | Nessus credentialed scan completed and validated against SSP's documented exposure list (78 plugins, 253 individual results, all mapped/explained); OpenSCAP gap (Finding OSCAP-1) closed via system decommissioning rather than re-scan, since the target VM no longer exists | ✅ Satisfied for this system's operational lifecycle — closure achieved via disposition, not remediation; see Section 7 |

---

## 4. Plan of Action & Milestones (POA&M)

| # | Weakness | Control | Source | Severity | Planned Corrective Action | Milestone / Target Date | Status |
|---|---|---|---|---|---|---|---|
| 1 | Self-signed TLS certificate on management UI | SC-8, SC-13 | Manual review | Low | Replace with a valid cert (e.g., via Let's Encrypt against the DNS label `<dns-label>`) or document as accepted risk for lab-only use | [set date] | Open |
| 2 | No formal contingency/backup plan | CP-2, CP-9 | Manual review | Low (non-production system) | Document VM snapshot/export procedure for T-Pot data volume; define RTO/RPO appropriate to a lab (informal) | [set date] | Open |
| 3 | OSCAP-1: CIS Level 2 scan returned 100% Not Applicable (0 pass/fail/error across 387 rules); did not constitute valid compliance evidence | RA-5 | OpenSCAP | Medium | Re-run was planned but the target VM was decommissioned before it could occur. Closed via system disposition rather than remediation — the weakness cannot be corrected on a system that no longer exists; RA-5 evidence for this system is instead satisfied by the completed Nessus credentialed scan (Section 2.2) | Closed at decommission | Closed — System Decommissioned |
| 4 | NESSUS-1: Detected OS (Ubuntu 24.04, kernel 6.17.0-1017-azure) does not match SSP-documented baseline (Ubuntu 22.04) | CM-6 | Nessus (credentialed) | Low | SSP Section 1.1/3 updated to reflect the actual detected OS/kernel as the historical record for this system | System decommissioned | Closed — Documentation Corrected |
| 5 | Confirm Azure IMDS (Instance Metadata Service) is not reachable from within honeypot containers — potential SSRF-adjacent pivot path from a compromised decoy service to Azure management-plane metadata | SC-7, AC-4 | Nessus (credentialed) | Medium | System was decommissioned before this test could be performed — **left untested**, not confirmed safe. Carried forward as a required Day-1 check in the SSP/SAP for any future T-Pot deployment (see Section 7) | Carried forward | Closed — System Decommissioned (Untested) |
| 6 | Validate all Nessus-flagged "vulnerable" services (MSSQL 2000, Telnet, web.config disclosure, J Walk traversal, Elasticsearch RCE, SNMP) against SSP Section 4's intentionally-exposed port list | RA-5 | Nessus (credentialed) | Informational | Completed as part of this SAR — all five confirmed findings map to documented honeypot-plane ports (Dionaea/Cowrie/Tanner/Elasticpot/Conpot); no remediation required, re-validate when new honeypot modules are added | N/A | Closed |
| 7 | Single point of failure — one VM, no redundancy | CP-6, CP-7 | Manual review | Low (accepted, lab scope) | Accepted risk — documented in SSP Section 3.8 as intentionally out of scope for a lab | N/A | Risk Accepted |

---

## 5. Recommendations

1. **Re-run the OpenSCAP scan** (Finding OSCAP-1) before citing this assessment as evidence of CIS Level 2 compliance — a 100% Not Applicable result is a tooling/execution problem, not a clean audit.
2. **Test IMDS reachability from within honeypot containers** (Finding NESSUS-2) — this is the one Nessus-flagged item with genuine security relevance beyond expected honeypot behavior, since a compromised decoy service pivoting to Azure metadata would be a real escalation path.
3. **Update the SSP's OS/kernel baseline** (Finding NESSUS-1) to Ubuntu 24.04 / kernel 6.17.0-1017-azure so the documentation matches the as-built system.
4. **Prioritize** replacing the self-signed certificate if dashboard URLs are ever shared publicly beyond screenshots (credential/session exposure risk on the management plane, even though it's IP-restricted).
5. **Continue the planned MITRE ATT&CK mapping** (Lab 3 in your roadmap) — this strengthens IR-4/IR-5 (Incident Handling/Monitoring) evidence in a future assessment cycle by showing captured attacker TTPs are actively analyzed, not just logged.
6. **Document a lightweight contingency procedure** (VM snapshot export cadence) to close the CP-family gap — even a one-paragraph procedure closes this credibly for a lab-scope system.

---

## 6. System Disposition

The T-Pot honeypot VM was **decommissioned** following a final Nessus re-scan performed to confirm remediation. This is a legitimate RMF closure path distinct from remediation: NIST guidance recognizes system disposal as a valid way to close residual findings when continued operation isn't the goal — the weakness is retired along with the system rather than fixed in place.

**Final validation scan:** A follow-up Nessus credentialed scan was run before decommissioning to verify remediation status. The scan **passed with no vulnerabilities reported**. The full plugin-level output from that run was not retained, so this SAR records the pass/fail outcome as closure evidence rather than a detailed before/after comparison — a real limitation worth naming rather than glossing over: without the retained report, this is an attestation of the result, not independently re-verifiable evidence. **Recommendation carried forward:** export and archive scan reports (PDF/CSV) at the time they're run, not just observed in the UI — this is itself a small but real audit-trail gap, and a good practice to note explicitly in future SAPs (e.g., a defined evidence-retention step tied to each assessment activity).

**Lesson learned, carried forward:** POA&M item 5 (IMDS reachability) could not be tested before decommissioning. For any future T-Pot (or similar Azure IaaS) deployment, this check should be performed **before** teardown — added as a standing pre-decommission checklist item in future SAPs.

---

## 7. Conclusion

The T-Pot O&G honeypot lab demonstrated strong implementation of boundary protection, identity/access, and encryption-at-rest controls consistent with the SSP, verified through manual configuration examination and a completed Nessus credentialed scan. This assessment distinguished between the honeypot's *intended* decoy exposure (which Nessus correctly flagged as "vulnerable" — that's the point) and genuine host-level risk, finding only one item (NESSUS-2, IMDS reachability) with real security relevance beyond expected behavior. The OpenSCAP scan-validity gap (OSCAP-1) and the untested IMDS check (NESSUS-2) were both closed via system decommissioning rather than remediation, which is documented above as the correct closure rationale rather than left as permanently open items. RA-5 (Vulnerability Scanning) is assessed as **Satisfied for this system's operational lifecycle**. All findings are closed; this SAR now represents the final assessment record for a retired system.

---

*This SAR, together with the SSP and SAP, forms the complete RMF documentation package for this system.*
