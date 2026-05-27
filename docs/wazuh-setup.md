# Wazuh — Secondary SIEM Setup

Second SIEM running alongside Splunk for dual-stack detection coverage. Wazuh Manager + Indexer + Dashboard on Ubuntu Server (ARM64) in UTM; first agent is the host macOS itself.

---

## Stack

| Component | Detail |
|---|---|
| Wazuh version | 4.13.1 (all-in-one) |
| Manager host | Ubuntu Server 24.04 ARM64 in UTM, IP `192.168.64.40` |
| Resources | 2 vCPU, 4 GB RAM, 15 GB disk |
| Dashboard URL | `https://192.168.64.40` (self-signed TLS) |
| First agent | macOS 26.5 (Apple Silicon) — host machine |

---

## Manager install (Ubuntu VM)

Single-script all-in-one install — installs Indexer, Manager, and Dashboard on one host:

```bash
curl -sO https://packages.wazuh.com/4.13/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

Installer prints admin credentials at the end — save them. Verify all three services:

```bash
sudo systemctl status wazuh-indexer wazuh-manager wazuh-dashboard --no-pager
```

---

## Agent deploy (macOS host)

1. Download the ARM64 package:
   ```bash
   curl -sO https://packages.wazuh.com/4.x/macos/wazuh-agent-4.13.1-1.arm64.pkg
   ```
2. Install:
   ```bash
   sudo installer -pkg ~/wazuh-agent-4.13.1-1.arm64.pkg -target /
   ```
3. Point the agent at the manager (the install-time env-file trick from the dashboard UI didn't apply on this run — fixed the config directly):
   ```bash
   sudo sed -i '' 's|MANAGER_IP|192.168.64.40|' /Library/Ossec/etc/ossec.conf
   ```
4. Enroll with the manager (port 1515):
   ```bash
   sudo /Library/Ossec/bin/agent-auth -m 192.168.64.40
   ```
5. Start the agent:
   ```bash
   sudo /Library/Ossec/bin/wazuh-control start
   ```

Dashboard → **Endpoints** → agent shows as `active` within ~15s.

---

## Gotchas hit during setup

1. **Dashboard's "Deploy new agent" one-liner doesn't enroll.** The `/tmp/wazuh_envs` trick is read by the installer's postinstall script only — if it fails (perms, path), the agent ships with `MANAGER_IP` as the literal placeholder in `ossec.conf` and refuses to start with `(4112): Invalid server address found: 'MANAGER_IP'`. Fix: `sed` the config and run `agent-auth` manually.

2. **Terminal paste wraps the curl one-liner.** macOS Terminal copy-paste from the dashboard splits the long install command across lines; zsh sees the URL on its own line and reports `no URL specified`. Workaround: run `curl -sO <url>` first as a clean single line, then the installer command separately.

3. **Two ports needed.** Agent → manager uses 1514/tcp (data) and 1515/tcp (enrollment). Both must be reachable. `nc -zv 192.168.64.40 1514` and `... 1515` to verify.

---

## What this adds to the lab

| Capability | Splunk side | Wazuh side |
|---|---|---|
| Log search/SPL | ✅ | — |
| Scheduled detection rules | ✅ (7 MITRE rules) | ✅ (built-in ruleset, ~3000 rules) |
| File Integrity Monitoring | — | ✅ (syscheckd) |
| Rootcheck / SCA | — | ✅ |
| Vulnerability detection | — | ✅ (CVE feeds) |
| MITRE ATT&CK mapping | ✅ (custom) | ✅ (built-in tagged rules) |

Splunk is the SPL-driven detection engineering surface; Wazuh is the agent-driven HIDS layer. Together they cover both network-shipped Windows event logs (Splunk UF) and host-resident integrity/posture (Wazuh agent).
