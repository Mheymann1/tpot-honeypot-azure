# Plan of Action & Milestones (POA&M)
## T-Pot Honeypot Lab — Azure Deployment

**System Name:** T-Pot Honeypot Lab
**System Owner:** Marcus Heymann
**Environment:** Azure Cloud — Lab/Research
**Assessment Date:** May–June 2026
**POA&M Version:** 1.0
**Framework:** NIST SP 800-53 Rev. 5 / RMF

---

## POA&M Overview

This POA&M documents all findings identified during security assessment of the T-Pot Honeypot Lab VM. Findings were identified through two assessment methods:

1. **Credentialed Vulnerability Scan** — Nessus Essentials 10.12.0 (June 3, 2026)
2. **Manual CIS Control Verification** — Mapped to NIST SP 800-53 Rev. 5 (May–June 2026)

| Category | Count |
|---|---|
| Open (Accepted Risk) | 7 |
| Closed (Remediated) | 8 |
| Total Findings | 15 |

---

## Section 1 — Open Items (Accepted Risk)

### POA&M-001
| Field | Detail |
|---|---|
| **Finding ID** | POA&M-001 |
| **Source** | Manual CIS Verification — Block 1 |
| **Weakness** | IP Forwarding Enabled (`net.ipv4.ip_forward = 1`) |
| **NIST Control** | SC-7 (Boundary Protection) |
| **Severity** | Low |
| **Description** | CIS Benchmark Level 2 requires `ip_forward = 0`. IP forwarding is currently enabled on the host OS. |
| **Risk Statement** | IP forwarding could allow traffic routing between network interfaces if exploited. |
| **Justification** | Docker Engine requires IP forwarding to route traffic between container networks and the host bridge interface. Disabling this parameter would terminate all T-Pot honeypot containers, defeating the purpose of the deployment. |
| **Compensating Controls** | UFW firewall default-deny on external interfaces; Azure NSG as outer boundary; all container traffic monitored via T-Pot ELK stack |
| **Residual Risk** | Low |
| **Scheduled Completion** | N/A — Permanent accepted risk for this deployment |
| **Status** | Accepted Risk |

---

### POA&M-002
| Field | Detail |
|---|---|
| **Finding ID** | POA&M-002 |
| **Source** | Manual CIS Verification — Block 4 |
| **Weakness** | Broad TCP/UDP Allow Rules in UFW |
| **NIST Control** | CM-7 (Least Functionality) |
| **Severity** | Low |
| **Description** | UFW ruleset permits all inbound TCP and UDP traffic to support honeypot services. This deviates from the principle of least functionality. |
| **Risk Statement** | Broad allow rules increase attack surface against the host OS. |
| **Justification** | T-Pot honeypot requires internet-wide accessibility across all ports to function as a threat intelligence collection platform. Restricting inbound ports would prevent attack telemetry collection. |
| **Compensating Controls** | All traffic captured and analyzed via T-Pot ELK stack; SSH management on non-standard port with key-based authentication; fail2ban active sshd jail; Azure NSG as outer boundary layer |
| **Residual Risk** | Low — monitored exposure by design |
| **Scheduled Completion** | N/A — Permanent accepted risk for this deployment |
| **Status** | Accepted Risk |

---

### POA&M-003
| Field | Detail |
|---|---|
| **Finding ID** | POA&M-003 |
| **Source** | Nessus Credentialed Scan — Plugin 73756 |
| **Weakness** | Microsoft SQL Server 2000 End-of-Life (Unsupported Version) |
| **NIST Control** | SI-2 (Flaw Remediation), SA-22 (Unsupported System Components) |
| **Severity** | Critical (CVSS 3.0: 10.0) |
| **CVE/Plugin** | Nessus Plugin 73756 |
| **Port** | 1433/tcp (MSSQL) |
| **Description** | Nessus detected Microsoft SQL Server 2000 (v8.0.528.0) — an end-of-life product no longer receiving security patches. |
| **Risk Statement** | End-of-life software may contain unpatched vulnerabilities exploitable by remote attackers. |
| **Investigation Finding** | This is the Dionaea honeypot container deliberately emulating Microsoft SQL Server 2000 to capture attacks targeting database services. No actual SQL Server installation exists on the host OS. This is a true positive against an intentional honeypot surface. |
| **Justification** | Dionaea honeypot emulates legacy and vulnerable services by design to attract and capture attack activity. Remediation would disable a core honeypot sensor. |
| **Compensating Controls** | All MSSQL connection attempts captured and logged via T-Pot ELK stack; host OS has no actual SQL Server installed; Azure NSG and UFW provide host-level boundary protection |
| **Residual Risk** | Low — no actual vulnerable software on host OS |
| **Scheduled Completion** | N/A — Permanent accepted risk for this deployment |
| **Status** | Accepted Risk |

---

### POA&M-004
| Field | Detail |
|---|---|
| **Finding ID** | POA&M-004 |
| **Source** | Nessus Credentialed Scan — Plugin 97834 |
| **Weakness** | Elasticsearch Transport Protocol Unspecified Remote Code Execution |
| **NIST Control** | SI-2 (Flaw Remediation), SC-7 (Boundary Protection) |
| **Severity** | Critical (CVSS 3.0: 9.8) |
| **Port** | 9200/tcp |
| **Description** | Nessus detected an Elasticsearch instance vulnerable to remote code execution via the transport protocol. Service is bound to all interfaces (0.0.0.0:9200). |
| **Risk Statement** | Remotely exploitable RCE vulnerability on a publicly accessible port could allow full system compromise. |
| **Investigation Finding** | Two Elasticsearch-related containers are present: (1) Elasticpot — a honeypot deliberately emulating a vulnerable Elasticsearch instance bound to 0.0.0.0:9200 by design; (2) Internal T-Pot Elasticsearch logging service bound to localhost only (127.0.0.1:64298). Nessus finding targets Elasticpot, not the internal logging database. |
| **Justification** | Elasticpot honeypot emulates vulnerable Elasticsearch to capture attacks targeting exposed database APIs — a common real-world attack vector. The internal Elasticsearch service is safely isolated to localhost. |
| **Compensating Controls** | Internal Elasticsearch bound to localhost only; all Elasticpot connections logged via T-Pot; Azure NSG and UFW provide boundary protection for host OS management plane |
| **Residual Risk** | Low — intentional honeypot, internal database not exposed |
| **Scheduled Completion** | N/A — Permanent accepted risk for this deployment |
| **Status** | Accepted Risk |

---

### POA&M-005
| Field | Detail |
|---|---|
| **Finding ID** | POA&M-005 |
| **Source** | Nessus Credentialed Scan — Plugin 42263 |
| **Weakness** | Unencrypted Telnet Server |
| **NIST Control** | SC-8 (Transmission Confidentiality), IA-2 (Identification and Authentication) |
| **Severity** | Medium (CVSS 3.0: 6.5) |
| **Port** | 23/tcp (Telnet) |
| **Description** | Nessus detected a Telnet service transmitting credentials in cleartext, susceptible to man-in-the-middle interception. |
| **Investigation Finding** | Port 23 is served by the Cowrie honeypot container, which emulates a Telnet login prompt to capture credential brute force attempts and attacker session interactions. No actual Telnet service is installed on the host OS. |
| **Justification** | Cowrie honeypot deliberately presents an unencrypted Telnet service to attract and log attacker activity. This is a core honeypot sensor function. |
| **Compensating Controls** | All Telnet session attempts captured and logged; host management access via SSH with key-based authentication only on non-standard port |
| **Residual Risk** | Low — no actual Telnet service on host OS |
| **Scheduled Completion** | N/A — Permanent accepted risk for this deployment |
| **Status** | Accepted Risk |

---

### POA&M-006
| Field | Detail |
|---|---|
| **Finding ID** | POA&M-006 |
| **Source** | Nessus Credentialed Scan — Plugin 121479 |
| **Weakness** | web.config File Information Disclosure |
| **NIST Control** | SI-12 (Information Management), SC-28 (Protection of Information at Rest) |
| **Severity** | Medium (CVSS 3.0: 5.3) |
| **Port** | 443/tcp |
| **Description** | Nessus retrieved a web.config file via GET request, potentially exposing configuration information to unauthenticated attackers. |
| **Investigation Finding** | Port 443 web services are served by the Tanner web application honeypot, which deliberately serves fake configuration files and vulnerable web application responses to capture attacker reconnaissance activity. |
| **Justification** | Tanner honeypot emulates vulnerable web applications by design. Serving web.config responses is an intentional capability to attract and log web-based attacks. |
| **Compensating Controls** | All web requests captured and logged via T-Pot ELK stack; no actual application configuration data exposed |
| **Residual Risk** | Low — fake configuration data served by honeypot |
| **Scheduled Completion** | N/A — Permanent accepted risk for this deployment |
| **Status** | Accepted Risk |

---

### POA&M-007
| Field | Detail |
|---|---|
| **Finding ID** | POA&M-007 |
| **Source** | Nessus Credentialed Scan — Plugin 11467 |
| **Weakness** | J Walk Application Server Encoded Directory Traversal |
| **NIST Control** | SI-10 (Information Input Validation) |
| **Severity** | Medium (CVSS 2.0: 5.0) |
| **Port** | 443/tcp |
| **Description** | Nessus detected a J Walk Application Server directory traversal vulnerability allowing arbitrary file access via encoded path sequences. |
| **Investigation Finding** | No output was recorded by Nessus — the traversal attempt triggered the detection signature but did not succeed. Port 443 is the Tanner web honeypot. EPSS score of 0.0028 indicates very low real-world exploit probability. Threat Recency shows no recorded events. |
| **Justification** | Finding is against the Tanner web honeypot container. No J Walk application server is installed on the host OS. Low EPSS and no recorded threat events further support accepted risk decision. |
| **Compensating Controls** | All connection attempts logged; no actual J Walk installation on host; Tanner honeypot captures traversal attempts as intelligence |
| **Residual Risk** | Very Low — unproven exploit, no real application present |
| **Scheduled Completion** | N/A — Permanent accepted risk for this deployment |
| **Status** | Accepted Risk |

---

## Section 2 — Closed Items (Remediated)

### POA&M-008
| Field | Detail |
|---|---|
| **Finding ID** | POA&M-008 |
| **Source** | Manual CIS Verification — Block 1 |
| **Weakness** | ICMP Send Redirects Enabled (`net.ipv4.conf.all.send_redirects = 1`) |
| **NIST Control** | SC-7 (Boundary Protection) |
| **Severity** | Low |
| **Remediation** | Set `send_redirects = 0` via sysctl and persisted in `/etc/sysctl.d/99-hardening.conf` |
| **Remediation Date** | May 2026 |
| **Verification** | `sysctl net.ipv4.conf.all.send_redirects` returns `0` |
| **Status** | ✅ Closed |

---

### POA&M-009
| Field | Detail |
|---|---|
| **Finding ID** | POA&M-009 |
| **Source** | Manual CIS Verification — Block 2 |
| **Weakness** | Password Maximum Age Set to 99999 Days |
| **NIST Control** | IA-5 (Authenticator Management) |
| **Severity** | Medium |
| **Remediation** | Set `PASS_MAX_DAYS 90` in `/etc/login.defs` |
| **Remediation Date** | May 2026 |
| **Verification** | `grep PASS_MAX_DAYS /etc/login.defs` returns `90` |
| **Status** | ✅ Closed |

---

### POA&M-010
| Field | Detail |
|---|---|
| **Finding ID** | POA&M-010 |
| **Source** | Manual CIS Verification — Block 2 |
| **Weakness** | Password Minimum Age Set to 0 Days |
| **NIST Control** | IA-5 (Authenticator Management) |
| **Severity** | Low |
| **Remediation** | Set `PASS_MIN_DAYS 1` in `/etc/login.defs` |
| **Remediation Date** | May 2026 |
| **Verification** | `grep PASS_MIN_DAYS /etc/login.defs` returns `1` |
| **Status** | ✅ Closed |

---

### POA&M-011
| Field | Detail |
|---|---|
| **Finding ID** | POA&M-011 |
| **Source** | Manual CIS Verification — Block 2 |
| **Weakness** | No Account Lockout Policy Configured |
| **NIST Control** | AC-7 (Unsuccessful Login Attempts) |
| **Severity** | High |
| **Remediation** | Configured PAM faillock in `/etc/pam.d/common-auth` — 5 failed attempts triggers 15-minute lockout |
| **Remediation Date** | May 2026 |
| **Verification** | `grep faillock /etc/pam.d/common-auth` confirms rules present |
| **Status** | ✅ Closed |

---

### POA&M-012
| Field | Detail |
|---|---|
| **Finding ID** | POA&M-012 |
| **Source** | Manual CIS Verification — Block 3 |
| **Weakness** | auditd Not Installed |
| **NIST Control** | AU-2 (Event Logging), AU-12 (Audit Record Generation) |
| **Severity** | High |
| **Remediation** | Installed auditd and audispd-plugins; deployed custom rules monitoring identity changes, privileged commands, and network configuration changes |
| **Remediation Date** | May 2026 |
| **Verification** | `systemctl is-active auditd` returns `active`; `auditctl -l` confirms rules loaded |
| **Status** | ✅ Closed |

---

### POA&M-013
| Field | Detail |
|---|---|
| **Finding ID** | POA&M-013 |
| **Source** | Manual CIS Verification — Block 4 |
| **Weakness** | UFW Firewall Inactive |
| **NIST Control** | SC-7 (Boundary Protection) |
| **Severity** | High |
| **Remediation** | Enabled UFW with default deny incoming; configured explicit allow rules for management ports and honeypot traffic |
| **Remediation Date** | May 2026 |
| **Verification** | `sudo ufw status verbose` shows Status: active, Default: deny (incoming) |
| **Status** | ✅ Closed |

---

### POA&M-014
| Field | Detail |
|---|---|
| **Finding ID** | POA&M-014 |
| **Source** | Manual CIS Verification — Block 4 |
| **Weakness** | fail2ban Not Installed |
| **NIST Control** | AC-7 (Unsuccessful Login Attempts), SI-4 (System Monitoring) |
| **Severity** | Medium |
| **Remediation** | Installed fail2ban; enabled and started service; sshd jail active monitoring SSH brute force attempts |
| **Remediation Date** | May 2026 |
| **Verification** | `sudo fail2ban-client status` shows 1 jail active (sshd) |
| **Status** | ✅ Closed |

---

### POA&M-015
| Field | Detail |
|---|---|
| **Finding ID** | POA&M-015 |
| **Source** | Manual CIS Verification — Block 4 |
| **Weakness** | No Explicit Management Port Rules Before UFW Activation |
| **NIST Control** | AC-17 (Remote Access), SC-7 (Boundary Protection) |
| **Severity** | Medium |
| **Remediation** | Configured explicit UFW allow rules for SSH management port, T-Pot web UI ports prior to enabling UFW default-deny policy |
| **Remediation Date** | May 2026 |
| **Verification** | `sudo ufw status verbose` confirms management ports explicitly allowed |
| **Status** | ✅ Closed |

---

## POA&M Summary

| ID | Finding | Source | Severity | NIST Control | Status |
|---|---|---|---|---|---|
| POA&M-001 | IP Forwarding Enabled | Manual | Low | SC-7 | Accepted Risk |
| POA&M-002 | Broad UFW Allow Rules | Manual | Low | CM-7 | Accepted Risk |
| POA&M-003 | MSSQL Server 2000 EOL (Dionaea) | Nessus | Critical | SI-2, SA-22 | Accepted Risk |
| POA&M-004 | Elasticsearch RCE (Elasticpot) | Nessus | Critical | SI-2, SC-7 | Accepted Risk |
| POA&M-005 | Unencrypted Telnet (Cowrie) | Nessus | Medium | SC-8, IA-2 | Accepted Risk |
| POA&M-006 | web.config Disclosure (Tanner) | Nessus | Medium | SI-12, SC-28 | Accepted Risk |
| POA&M-007 | J Walk Directory Traversal (Tanner) | Nessus | Medium | SI-10 | Accepted Risk |
| POA&M-008 | ICMP Send Redirects Enabled | Manual | Low | SC-7 | ✅ Closed |
| POA&M-009 | Password Max Age 99999 Days | Manual | Medium | IA-5 | ✅ Closed |
| POA&M-010 | Password Min Age 0 Days | Manual | Low | IA-5 | ✅ Closed |
| POA&M-011 | No Account Lockout Policy | Manual | High | AC-7 | ✅ Closed |
| POA&M-012 | auditd Not Installed | Manual | High | AU-2, AU-12 | ✅ Closed |
| POA&M-013 | UFW Firewall Inactive | Manual | High | SC-7 | ✅ Closed |
| POA&M-014 | fail2ban Not Installed | Manual | Medium | AC-7, SI-4 | ✅ Closed |
| POA&M-015 | No Management Port Rules Pre-UFW | Manual | Medium | AC-17, SC-7 | ✅ Closed |

---

---

*POA&M prepared by [@marcusheymann](https://www.linkedin.com/in/mheymann1) | OT/ICS Cybersecurity Analyst*
*Assessment tools: Nessus Essentials 10.12.0 | OpenSCAP 1.3.9 | Manual CIS Verification*
*Framework: NIST SP 800-53 Rev. 5 | RMF*
