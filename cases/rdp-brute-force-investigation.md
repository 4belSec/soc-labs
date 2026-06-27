# Incident Report: RDP Brute Force Attack Detection & Investigation

**Analyst:** Abel (4belSec)
**Date:** June 26, 2026
**Environment:** Self-built SOC Home Lab (Proxmox VE, Splunk Enterprise, Sysmon)
**Severity:** High (simulated)
**Status:** Resolved — Controlled simulation, root cause identified, detection validated

---

## Summary

A brute force attack against RDP (port 3389) was simulated against a Windows 10 endpoint within the home lab using Hydra from a Kali Linux attack host. The attack consisted of 9 failed authentication attempts followed by 1 successful login using a known-valid password, completed in approximately 18 seconds. The attack was fully captured via Windows Security event logs (forwarded through Splunk Universal Forwarder), investigated using Splunk Search Processing Language (SPL), and a working detection rule was built and validated against the activity.

---

## Environment / Architecture

| Component | Role | Details |
|---|---|---|
| Kali-Attacker | Attack host | Kali Linux, Hydra v9.7 |
| WIN10-Endpoint | Target | Windows 10 Pro, RDP enabled, Security auditing on Logon (Success/Failure) |
| Splunk-SIEM | Log aggregation & analysis | Splunk Enterprise 10.4.0, Universal Forwarder ingesting `WinEventLog:Security` |

All hosts run as VMs under Proxmox VE, connected over an internal `192.168.12.0/24` network, with remote access via Tailscale.

---

## Attack Execution

**Tool:** Hydra
**Target:** `rdp://192.168.12.168:3389`
**Method:** Single-threaded dictionary attack against a known username, using a 10-entry custom wordlist with the real password placed last (to produce a controlled, observable success).

```
hydra -l Analyst -P passwords.txt rdp://192.168.12.168 -t 1 -V
```

**Result:**
```
[3389][rdp] host: 192.168.12.168   login: Analyst   password: ********
1 of 1 target successfully completed, 1 valid password found
```

9 of 10 attempts failed before the correct password was found. Total attack duration: ~18 seconds (22:52:38 → 22:52:56 local time).

---

## Detection & Investigation (Splunk)

### Step 1 — Confirm log visibility

Before the attack, `Security` log ingestion was not yet configured on the forwarder (only Sysmon was). The `inputs.conf` on the Windows endpoint was updated to forward `WinEventLog:Security`, and the forwarder service was restarted.

```
[WinEventLog://Security]
disabled = false
index = main
sourcetype = WinEventLog:Security
```

### Step 2 — Identify the failed logon cluster

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4625 Logon_Type=3
| bin _time span=1m
| stats count as failed_logons by _time, Account_Name
| where failed_logons >= 5
```

**Result:** 9 failed logons for account `Analyst` within a single 1-minute bucket — well above the 5-attempt threshold.

Each failure carried `Status=0xC000006D` / `Sub_Status=0xC000006A`, which translates to **"valid account name, incorrect password"** — a meaningful detail, since it indicates the attacker already had a confirmed valid username and was only guessing credentials (as opposed to a broader, unauthenticated scan).

### Step 3 — Correlate failures with the eventual success

```spl
index=main sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4624) Account_Name=Analyst Logon_Type=3
| sort _time
| streamstats count(eval(EventCode=4625)) as fail_count window=20 current=true
| eval status=if(EventCode=4624 AND fail_count>=5,"BRUTE FORCE SUCCESS","-")
| table _time, EventCode, Account_Name, Logon_Type, Status, Sub_Status, fail_count, status
```

**Result:** `fail_count` climbed from 0 to 9 across the failed attempts, and the eventual `EventCode=4624` (successful logon, network logon type) was flagged `BRUTE FORCE SUCCESS` — confirming the detection logic correctly ties the failure spike to the moment of compromise.

---

## Timeline

| Time | Event | Detail |
|---|---|---|
| 22:52:38.454 | 4625 (Failure #1) | Logon_Type=3, Status 0xC000006D |
| 22:52:40 – 22:52:54 | 4625 (Failures #2–9) | Same status/sub-status, ~2 sec apart |
| 22:52:56.611 | 4624 (Success) | Logon_Type=3 — attacker authenticated |

---

## Detection Rule (Production-Ready Logic)

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4625 Logon_Type=3
| bin _time span=1m
| stats count as failed_logons by _time, Account_Name
| where failed_logons >= 5
```

**Logic:** Alert when 5 or more failed network logons (Logon_Type=3) occur for the same account within a 1-minute window. This threshold balances sensitivity (catching fast brute-force tools like Hydra) against false positives (a user mistyping their password 2–3 times).

**Recommended follow-up actions in a real SOC:**
- Auto-disable or flag the account after threshold is hit
- Alert on **successful** logon immediately following a failure spike (highest-fidelity signal of compromise)
- Cross-reference source IP against threat intel / geolocation for external-facing RDP
- If RDP is internet-facing, this is a strong argument for disabling direct RDP exposure in favor of a VPN or RDP gateway with MFA

---

## Key Takeaways

- Validated full attack lifecycle visibility: attack tool → Windows Security log → Splunk Universal Forwarder → SIEM search.
- Practiced root-cause troubleshooting of log pipeline gaps (missing `inputs.conf` stanza) before relying on the data.
- Built and validated a working brute-force detection query from raw logs — not just theoretical SPL.
- Identified a meaningful artifact (`Sub_Status=0xC000006A`) that distinguishes "valid user, wrong password" from broader unauthenticated scanning — the kind of detail that matters in real triage.
