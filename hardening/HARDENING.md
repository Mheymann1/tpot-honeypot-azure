# Security Hardening Report — T-Pot Honeypot VM

> **Manual control verification mapped to NIST SP 800-53 Rev. 5**
> **Host:** Ubuntu 24.04.4 LTS | Azure VM | T-Pot 24.x
> **Date:** May–June 2026
> **Controls verified:** 34 | **Passing or remediated:** 33/34 (97%)

---

## Table of Contents

- [Background — OpenSCAP Limitation](#background--openscap-limitation)
- [Block 1 — Kernel & Network Hardening](#block-1--kernel--network-hardening)
- [Block 2 — Authentication & Account Policy](#block-2--authentication--account-policy)
- [Block 3 — Audit & Logging](#block-3--audit--logging)
- [Block 4 — Firewall & Services](#block-4--firewall--services)
- [Block 5 — File Permissions & SUID](#block-5--file-permissions--suid)
- [Accepted Risk Statements](#accepted-risk-statements)
- [Hardening Summary](#hardening-summary)

---

## Background — OpenSCAP Limitation

**Tool:** OpenSCAP 1.3.9 | **Profile:** CIS Level 2 Server | **Benchmark:** ssg-ubuntu2204-ds.xml

| Result | Count |
|---|---|
| Pass | 0 |
| Fail | 0 |
| Not Applicable | 387 |
| Error | 0 |

**Score: 0/100**

All 387 rules returned `notapplicable`. Root cause: Docker's containerized network stack prevents OpenSCAP's OVAL probes from satisfying prerequisite checks before evaluating rules. This is a tooling limitation, not a compliance failure.

**Response:** Manual control verification performed against NIST SP 800-53 Rev. 5 control families. Results documented below.

---

## Block 1 — Kernel & Network Hardening

**NIST Controls:** SC-5, SC-7, AC-17, SI-16, CM-6, AC-6

| Parameter | Value | Status | NIST |
|---|---|---|---|
| `net.ipv4.accept_redirects` | 0 | ✅ Pass | SC-7 |
| `net.ipv4.conf.all.accept_source_route` | 0 | ✅ Pass | SC-7 |
| `net.ipv4.tcp_syncookies` | 1 | ✅ Pass | SC-5 |
| `kernel.randomize_va_space` | 2 (Full ASLR) | ✅ Pass | SI-16 |
| `kernel.dmesg_restrict` | 1 | ✅ Pass | AC-6 |
| `fs.protected_hardlinks` | 1 | ✅ Pass | CM-6 |
| `fs.protected_symlinks` | 1 | ✅ Pass | CM-6 |
| `net.ipv4.ip_forward` | 1 | ⚠️ Accepted Risk | SC-7 |
| `net.ipv4.conf.all.send_redirects` | 1 → **0** | 🔧 Remediated | SC-7 |

**Remediation applied:**
```bash
sudo sysctl -w net.ipv4.conf.all.send_redirects=0
sudo sysctl -w net.ipv4.conf.default.send_redirects=0
echo "net.ipv4.conf.all.send_redirects=0" | sudo tee -a /etc/sysctl.d/99-hardening.conf
echo "net.ipv4.conf.default.send_redirects=0" | sudo tee -a /etc/sysctl.d/99-hardening.conf
```

---

## Block 2 — Authentication & Account Policy

**NIST Controls:** IA-5, AC-7, AC-6

| Control | Before | After | Status | NIST |
|---|---|---|---|---|
| `PASS_MAX_DAYS` | 99999 | **90** | 🔧 Remediated | IA-5 |
| `PASS_MIN_DAYS` | 0 | **1** | 🔧 Remediated | IA-5 |
| `PASS_WARN_AGE` | 7 | 7 | ✅ Pass | IA-5 |
| `ENCRYPT_METHOD` | SHA512 | SHA512 | ✅ Pass | IA-5 |
| Account lockout (faillock) | Not configured | **5 attempts / 15 min** | 🔧 Remediated | AC-7 |
| Root login | Disabled (Azure) | Disabled | ✅ Pass | AC-6 |

**Remediations applied:**
```bash
# Password aging
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/' /etc/login.defs
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/' /etc/login.defs

# PAM faillock — added to /etc/pam.d/common-auth
# Above pam_unix.so:
auth required pam_faillock.so preauth silent deny=5 unlock_time=900
# Below pam_unix.so:
auth [default=die] pam_faillock.so authfail deny=5 unlock_time=900
```

---

## Block 3 — Audit & Logging

**NIST Controls:** AU-2, AU-12, SI-4

| Control | Status | Notes |
|---|---|---|
| `auditd` service | ✅ Pass | Active, enabled on boot |
| `rsyslog` service | ✅ Pass | Active |
| `/var/log/audit/audit.log` | ✅ Pass | 1.4MB, actively writing |
| `/var/log/auth.log` | ✅ Pass | Present |
| `/var/log/syslog` | ✅ Pass | 39MB, healthy |
| Identity change monitoring | ✅ Pass | passwd, shadow, sudoers watched |
| Privileged command auditing | ✅ Pass | root execve tracked |
| Network change auditing | ✅ Pass | hostname, /etc/hosts monitored |

**Note:** auditd was not present on initial deployment. Installed as part of this hardening exercise.

**Audit rules deployed** (`/etc/audit/rules.d/hardening.rules`):
```bash
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /var/log/auth.log -p wa -k auth_log
-a always,exit -F arch=b64 -S execve -F euid=0 -k privileged
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_changes
-w /etc/hosts -p wa -k network_changes
```

---

## Block 4 — Firewall & Services

**NIST Controls:** SC-7, CM-7, AC-17, AC-7

| Control | Before | After | Status | NIST |
|---|---|---|---|---|
| UFW firewall | Inactive | **Active** | 🔧 Remediated | SC-7 |
| Default deny incoming | N/A | **Enabled** | 🔧 Remediated | SC-7 |
| SSH management port | Open (no FW) | **Explicitly allowed** | 🔧 Remediated | AC-17 |
| fail2ban | Not installed | **Active, sshd jail** | 🔧 Remediated | AC-7 |
| T-Pot honeypot ports | Open | **Explicitly allowed** | ✅ Pass | CM-7 |

**UFW ruleset applied:**
```bash
sudo ufw allow <SSH_PORT>/tcp comment 'SSH management'
sudo ufw allow <TPOT_WEB_PORT>/tcp comment 'T-Pot web alt'
sudo ufw allow <TPOT_UI_PORT>/tcp comment 'T-Pot web UI'
sudo ufw allow <TPOT_UI_HTTPS_PORT>/tcp comment 'T-Pot web UI HTTPS'
sudo ufw allow proto tcp from any to any comment 'T-Pot honeypot TCP'
sudo ufw allow proto udp from any to any comment 'T-Pot honeypot UDP'
sudo ufw --force enable
```

---

## Block 5 — File Permissions & SUID

**NIST Controls:** CM-6, AC-6

| Control | Value | Status | NIST |
|---|---|---|---|
| `/etc/passwd` permissions | 0644 root:root | ✅ Pass | AC-6 |
| `/etc/shadow` permissions | 0640 root:shadow | ✅ Pass | AC-6 |
| `/etc/gshadow` permissions | 0640 root:shadow | ✅ Pass | AC-6 |
| World-writable directories | /tmp, /var/tmp, /var/crash only | ✅ Pass | CM-6 |
| SUID binaries | Standard system binaries only | ✅ Pass | AC-6 |

No remediation required. All standard Ubuntu system binaries only — no anomalous SUID binaries found.

---

## Accepted Risk Statements

### AR-001 — IP Forwarding Enabled

| Field | Detail |
|---|---|
| **Control** | NIST SC-7 |
| **Parameter** | `net.ipv4.ip_forward = 1` |
| **Finding** | CIS Benchmark requires `ip_forward = 0` |
| **Justification** | Docker requires IP forwarding to route traffic between container networks and the host. Disabling would terminate all T-Pot honeypot containers. |
| **Compensating Controls** | UFW firewall with explicit allow rules; Azure NSG as outer boundary; all container traffic monitored via T-Pot ELK stack |
| **Risk Level** | Low — mitigated by layered boundary controls |

### AR-002 — Honeypot Ports Open to Internet

| Field | Detail |
|---|---|
| **Control** | NIST CM-7 |
| **Finding** | Broad TCP/UDP allow rules in UFW |
| **Justification** | T-Pot is a honeypot by design. Internet accessibility is a functional requirement — restricting inbound ports would prevent attack telemetry collection. |
| **Compensating Controls** | All traffic captured via T-Pot ELK stack; SSH on non-standard port with key-based auth and fail2ban; Azure NSG as outer layer |
| **Risk Level** | Accepted — intentional attack surface by design |

---

## Hardening Summary

| Block | Domain | Controls | Pass | Remediated | Accepted Risk |
|---|---|---|---|---|---|
| 1 | Kernel & Network | 9 | 7 | 1 | 1 |
| 2 | Authentication | 6 | 3 | 3 | 0 |
| 3 | Audit & Logging | 8 | 8 | 0 | 0 |
| 4 | Firewall & Services | 6 | 2 | 4 | 0 |
| 5 | File Permissions | 5 | 5 | 0 | 0 |
| **Total** | | **34** | **25** | **8** | **1** |

**Controls passing or remediated: 33/34 (97%)**

---

*Hardening performed by [@marcusheymann](https://www.linkedin.com/in/marcusheymann) | OT/ICS Cybersecurity Analyst*
*Framework: NIST SP 800-53 Rev. 5 | Tool: OpenSCAP 1.3.9 (limitation documented above)*
