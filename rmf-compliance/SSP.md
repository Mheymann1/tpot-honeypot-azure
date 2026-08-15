# System Security Plan (SSP)

**System Name:** T-Pot O&G Threat Intelligence Honeypot Lab (TPOT-HIVE-LAB)
**Prepared By:** Marcus
**Date:** August 12, 2026
**Baseline:** NIST SP 800-53 Rev. 5, Moderate Impact
**Authorization Boundary:** Single Azure IaaS deployment, `<resource-group>` resource group

> **Note on scope:** This SSP documents a self-hosted research/portfolio lab, not a production or government system. It is written to a Moderate baseline to demonstrate full RMF documentation practice (per the target JD's SSP/SAR/POA&M/SAP requirements) rather than because the system processes sensitive data. Where a control is Not Applicable to a single-VM lab, that is stated explicitly rather than fabricated.

---

## 1. System Identification

| Field | Value |
|---|---|
| System Name | T-Pot O&G Threat Intelligence Honeypot Lab |
| System Owner | Marcus |
| System Type | Minor Application / General Support System (single-host lab) |
| Environment | Microsoft Azure (IaaS), Public Cloud |
| Region | East US |
| FIPS 199 Categorization | Confidentiality: Low, Integrity: Moderate, Availability: Low → **Moderate (high water mark)** |
| Operational Status | Operational (research/demonstration) |
| Purpose | Deploy a high-interaction, multi-protocol honeypot (T-Pot HIVE, including Conpot ICS/SCADA emulation) to collect real-world attacker telemetry against IT and OT/ICS protocols, for security research, threat-intel reporting, and portfolio demonstration targeting the Oil & Gas sector. |

### 1.1 System Description

The system is a single Azure Virtual Machine running T-Pot (Deutsche Telekom's multi-honeypot platform, HIVE edition), which runs 20+ containerized honeypot services behind an ELK (Elasticsearch/Logstash/Kibana) stack. The system deliberately exposes emulated services to the internet to attract and record unauthorized access attempts; no production data, credentials, or business systems are connected to it.

Of particular relevance to the O&G use case, **Conpot** is configured with the **Guardian AST** template, which emulates an Automatic Tank Gauge (ATG) — a real-world petroleum storage monitoring device — to capture ICS/SCADA-specific attacker behavior (Modbus, S7comm, BACnet, ENIP protocol probing).

### 1.2 Authorization Boundary

The authorization boundary is limited to Azure resources inside `<resource-group>`:

- 1x Azure VM (`<vm-name>`, Standard_D4s_v3, Ubuntu 22.04 LTS, 256GB Premium SSD)
- 1x Virtual Network (`<vnet-name>`, <vnet-cidr>) with dedicated subnet (`<subnet-name>`, <subnet-cidr>)
- 1x Network Security Group (`<nsg-name>`)
- 1x Static Public IP (`<public-ip-name>`)
- 1x Key Vault (`<key-vault-name>`) — Azure Disk Encryption key storage
- 1x Log Analytics Workspace (`<log-analytics-workspace>`) — Azure Monitor / Defender integration
- Microsoft Defender for Cloud (Defender for Servers, Standard tier)
- Docker-hosted application layer: 20+ honeypot daemons + ELK stack + NGINX reverse proxy, managed by the T-Pot install

**Interconnections:** None to production, corporate, or third-party systems. Outbound: package repos, T-Pot GitHub repo (install-time only), Azure platform services (Monitor, Key Vault, Defender). Inbound: public internet (honeypot plane, intentionally open) and the system owner's static residential/analyst IP (management plane only).

### 1.3 System Environment / Architecture

```
                         Internet
                            │
                 ┌──────────┴──────────┐
                 │   Azure Public IP    │  (<public-ip-name>, Static, Std SKU)
                 └──────────┬──────────┘
                            │
                 ┌──────────┴──────────┐
                 │   <nsg-name> (NSG)     │
                 │  - Mgmt: analyst IP  │
                 │  - Honeypot: 0.0.0.0/0 (by design)
                 │  - Priority 4096: Deny-All
                 └──────────┬──────────┘
                            │
                 ┌──────────┴──────────┐
                 │  <vnet-name> (<vnet-cidr>)
                 │  <subnet-name> (<subnet-cidr>)
                 └──────────┬──────────┘
                            │
                 ┌──────────┴──────────┐
                 │  <vm-name>    │
                 │  Ubuntu 22.04 LTS    │
                 │  Disk: ADE-encrypted │
                 │ ┌──────────────────┐ │
                 │ │ Docker Engine     │ │
                 │ │ - Cowrie, Dionaea,│ │
                 │ │   Conpot(Guardian │ │
                 │ │   AST), Honeytrap,│ │
                 │ │   + 17 more       │ │
                 │ │ - ELK stack       │ │
                 │ │ - NGINX (TLS)     │ │
                 │ └──────────────────┘ │
                 └──────────┬──────────┘
                            │
                 ┌──────────┴──────────┐
                 │ Log Analytics /      │
                 │ Defender for Cloud   │
                 └──────────────────────┘
```

### 1.4 Data Types Processed

- Attacker network telemetry (source IPs, ports, protocols, payloads, credentials attempted)
- Malware samples captured by Dionaea
- No PII, no production business data, no real ICS/control data (Conpot is a simulation only)

---

## 2. Roles and Responsibilities

| Role | Assigned To | Responsibility |
|---|---|---|
| System Owner / ISSO | Marcus | Overall accountability, control implementation, POA&M tracking |
| Authorizing Official (AO) equivalent | Marcus (self-authorized, lab context) | Risk acceptance for lab operation |
| Cloud Service Provider | Microsoft Azure | Physical/infrastructure security, hypervisor isolation (per Azure shared responsibility model) |

---

## 3. Control Implementation Summary

Controls below reflect what is **actually implemented** in the deployment guide followed for this lab. Controls are organized by family; only families with a direct, demonstrable implementation are detailed. Remaining Moderate-baseline controls not yet implemented are tracked in the accompanying POA&M (see SAR).

### 3.1 Access Control (AC)

| Control | Implementation |
|---|---|
| AC-3 Access Enforcement | NSG rules split the system into a management plane (locked to analyst IP) and a honeypot plane (intentionally open, by design of the honeypot's function) |
| AC-4 Information Flow Enforcement | Priority-ordered NSG rules; explicit deny-all fallback rule (priority 4096) blocks any traffic not explicitly permitted |
| AC-6 Least Privilege | No root SSH login (`PermitRootLogin no`); dedicated non-root admin account (`<admin-username>`) |
| AC-7 Unsuccessful Logon Attempts | `MaxAuthTries 3` in sshd_config; fail2ban jail on the management SSH port (64295) with 3-attempt threshold, 1-hour ban |
| AC-17 Remote Access | SSH key-based only; password authentication disabled (`PasswordAuthentication no`); management SSH restricted by NSG to analyst's static IP |

### 3.2 Identification and Authentication (IA)

| Control | Implementation |
|---|---|
| IA-2 Identification and Authentication (Org Users) | SSH public-key authentication enforced (`PubkeyAuthentication yes`, password auth disabled) |
| IA-5 Authenticator Management | SSH key pair generated at provisioning; T-Pot Web UI / Kibana protected by unique credentials set at install |

### 3.3 System and Communications Protection (SC)

| Control | Implementation |
|---|---|
| SC-5 Denial of Service Protection | Kernel-level SYN flood protection (`tcp_syncookies=1`, `tcp_max_syn_backlog=2048`) |
| SC-7 Boundary Protection | NSG enforces segmented boundary between internet, management plane, and honeypot plane; deny-all default |
| SC-8 Transmission Confidentiality/Integrity | Kibana and T-Pot Web UI served over HTTPS/TLS via NGINX reverse proxy (self-signed cert in lab) |
| SC-13 Cryptographic Protection | Azure Disk Encryption (ADE) via Key Vault (`<key-vault-name>`) for OS and data disks |
| SC-20/21 Secure Name/Address Resolution | Static DNS label on public IP (`<dns-label>`) via Azure |

### 3.4 System and Information Integrity (SI)

| Control | Implementation |
|---|---|
| SI-2 Flaw Remediation | `unattended-upgrades` enabled for automatic OS security patching |
| SI-3 Malicious Code Protection | Log4Shell-specific detector (log4pot honeypot module); Dionaea captures malware samples for analysis rather than execution on the host |
| SI-4 Information System Monitoring | Microsoft Defender for Cloud (Defender for Servers, Standard tier) + Log Analytics workspace ingesting VM telemetry; fail2ban as host-level intrusion monitoring on the management plane |
| SI-11 Error Handling | Centralized logging to ELK stack; log rotation configured (30-day retention, daily rotation, compression) |

### 3.5 Audit and Accountability (AU)

| Control | Implementation |
|---|---|
| AU-4 Audit Storage Capacity | Disk sized (256GB Premium SSD) with log rotation to manage capacity; `docker system df` monitored |
| AU-6 Audit Review, Analysis, Reporting | Kibana dashboards (Attack Map, Cowrie, Dionaea, Conpot, Suricata IDS, CVE/log4pot) used for ongoing review |
| AU-11 Audit Record Retention | Logrotate policy: daily rotation, 30-day retention, compressed |

### 3.6 Configuration Management (CM)

| Control | Implementation |
|---|---|
| CM-6 Configuration Settings | Documented, repeatable deployment (this SSP + deployment runbook); sysctl hardening baseline applied via `/etc/sysctl.d/99-tpot-hardening.conf` |
| CM-7 Least Functionality | Only ports required for honeypot function or restricted management access are opened; all else explicitly denied |

### 3.7 Risk Assessment (RA)

| Control | Implementation |
|---|---|
| RA-5 Vulnerability Scanning | OpenSCAP CIS Level 2 audit performed against the host; Nessus credentialed scan performed against the VM (see SAR for results) |

### 3.8 Contingency Planning (CP) — *Not Applicable / Minimal*

Given the disposable, non-production nature of the system, formal contingency planning (CP-2 Contingency Plan, CP-9 Backup) is **not implemented** and is accepted as a residual gap appropriate to a lab environment — tracked in the POA&M rather than falsely claimed as implemented. Azure platform durability (managed disks) provides baseline resilience.

---

## 4. Interconnections and Ports/Protocols/Services

| Plane | Ports | Access |
|---|---|---|
| Management | TCP 64295 (SSH), 64296 (Kibana), 64297 (T-Pot Web UI) | Restricted to analyst static IP only |
| Honeypot – IT | TCP 21,22,23,25,80,110,143,443,445,1080,1433,3306,3389,5900,8080,8443 | Open to internet (by design) |
| Honeypot – ICS/SCADA | TCP 102 (S7comm), 502 (Modbus), 44818 (ENIP), 47808 (BACnet); UDP 502, 47808, 161, 162 (SNMP) | Open to internet (by design) |
| Honeypot – Extended | TCP 5555, 6667, 8888, 9200, 11211, 27017, 50000-50001 | Open to internet (by design) |
| Default | All other | Explicit deny (NSG priority 4096) |

---

## 5. Rules of Behavior

- System is a decoy/research asset only; no real credentials, PII, or production data may ever be placed on it.
- Management access is restricted to the system owner's authorized IP address; NSG source IP must be updated if the analyst's IP changes.
- Captured malware samples (Dionaea) are handled as hostile artifacts — analyzed in isolation, never executed on the host or exfiltrated to non-lab systems.
- Public-facing dashboards/screenshots (e.g., for LinkedIn) must not disclose the live public IP, internal analyst IP, or credentials.

---

*This SSP should be read together with the accompanying Security Assessment Plan (SAP) and Security Assessment Report (SAR).*
