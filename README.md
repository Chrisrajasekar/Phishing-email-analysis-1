# 🛡️ Phishing Email Analysis — Norton Antivirus Brand Impersonation

> **Case ID:** PHI-2023-1105-001  
> **Classification:** Phishing / Scareware / Brand Impersonation  
> **Verdict:** ⛔ MALICIOUS  
> **Analyst Level:** SOC Tier-2 / Senior Analyst  

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [The Phishing Email — Annotated](#the-phishing-email--annotated)
3. [What to Check — Analysis Methodology](#what-to-check--analysis-methodology)
4. [Step 1 — Email Header Analysis](#step-1--email-header-analysis)
5. [Step 2 — URL Analysis & Safe Expansion](#step-2--url-analysis--safe-expansion)
6. [Step 3 — VirusTotal Scan](#step-3--virustotal-scan)
7. [Step 4 — AbuseIPDB Lookup](#step-4--abuseipdb-lookup)
8. [Step 5 — WHOIS / IP Lookup](#step-5--whois--ip-lookup)
9. [Step 6 — Content & Social Engineering Analysis](#step-6--content--social-engineering-analysis)
10. [IOC Summary](#ioc-summary)
11. [Microsoft Sentinel Detection Rule (KQL)](#microsoft-sentinel-detection-rule-kql)
12. [Recommended Actions](#recommended-actions)
13. [Tools Reference](#tools-reference)
14. [Project Structure](#project-structure)

---

## Overview

This repository documents a **real-world phishing email** impersonating Norton Antivirus, received on **November 5, 2023**. It serves as a hands-on SOC analyst case study demonstrating:

- Full email header decomposition
- IOC (Indicator of Compromise) extraction
- Threat intelligence lookups (VirusTotal, AbuseIPDB, URLhaus, WHOIS)
- Microsoft 365 tenant abuse detection
- Social engineering tactic identification
- Microsoft Sentinel KQL detection rule
- Analyst response playbook

> ⚠️ **Disclaimer:** All IOCs documented here are from a confirmed phishing email submitted to a honeypot address (`phishing@pot`). URLs are **not** to be visited directly. Use sandbox tools only.

---

## The Phishing Email — Annotated

![Phishing email screenshot with annotations](screenshots/phishing_email_raw.png)

### At a Glance — Every Red Flag

| Field | Value | Flag |
|---|---|---|
| Display Name | `Norton - Anti Virus` | 🔴 SPOOFED — not from norton.com |
| Actual From | `0u4cw6o4bk@oueac.onmicrosoft.com` | 🔴 Random M365 throwaway tenant |
| Envelope From | `l1ko0jy17005odr@oueac.onmicrosoft.com` | 🟡 Mismatch from display address |
| Reply-To | Not visible — likely Gmail / unknown | 🟡 Escalate for header review |
| Subject | `Your Antivirus Subscription Has Expired...` | 🔴 Fear + urgency language |
| URL | `https://t.co/tNeajXlbGt` | 🔴 URL shortener hiding destination |
| Attachment | None | ✅ No attachment in this sample |
| SPF / DKIM / DMARC | Likely PASS (M365 bypass technique) | 🔴 Auth bypass — do not trust |

---

## What to Check — Analysis Methodology

```
EMAIL RECEIVED
      │
      ▼
┌─────────────────────────────────────┐
│  1. HEADER ANALYSIS                 │
│     From / Envelope-From / Reply-To │
│     SPF · DKIM · DMARC results      │
│     Received chain & hop IPs        │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  2. URL / LINK ANALYSIS             │
│     Extract all hyperlinks          │
│     Expand shorteners (safely)      │
│     Check redirects & final dest    │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  3. THREAT INTELLIGENCE             │
│     VirusTotal  → URL + domain scan │
│     AbuseIPDB   → IP reputation     │
│     URLhaus     → malware URL DB    │
│     PhishTank   → phishing database │
│     URLScan.io  → safe screenshot   │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  4. WHOIS / IP INVESTIGATION        │
│     Domain registration age        │
│     Registrar & registrant         │
│     ASN & hosting provider          │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  5. CONTENT ANALYSIS                │
│     Brand impersonation             │
│     Social engineering tactics      │
│     Grammar / quality flags         │
│     Psychological manipulation      │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  6. RESPONSE & HUNTING              │
│     Block IOCs at gateway           │
│     Sentinel hunt for more victims  │
│     Check proxy logs for clicks     │
│     Report to brand + abuse contact │
└─────────────────────────────────────┘
```

---

## Step 1 — Email Header Analysis

### How to Get Raw Headers

| Client | How to Access |
|---|---|
| Outlook (Web) | `...` → View → View message source |
| Outlook (Desktop) | File → Properties → Internet headers |
| Gmail | Three dots → Show original |
| Apple Mail | View → Message → All Headers |

### What We Found

**🔴 CRITICAL — Display Name Spoofing**
```
From: "Norton - Anti Virus" <0u4cw6o4bk@oueac.onmicrosoft.com>
```
The display name says "Norton - Anti Virus" but the actual sending address is a **throwaway Microsoft 365 tenant** (`oueac.onmicrosoft.com`) — completely unrelated to `norton.com`.

**🔴 CRITICAL — Microsoft 365 Tenant Abuse (Auth Bypass)**

This is the most important finding. The attacker created a **free Microsoft 365 tenant** (`oueac.onmicrosoft.com`) to send this email. Because Microsoft's own infrastructure sends it:

- **SPF → PASS** (Microsoft's SPF covers all M365 tenants)
- **DKIM → PASS** (M365 signs all outbound by default)
- **DMARC → PASS** (onmicrosoft.com has a lenient `p=none` policy)

> ⚠️ **Key Lesson:** An email that passes SPF + DKIM + DMARC is **not necessarily legitimate**. Always check the actual sending domain, not just auth results.

**🟡 HIGH — Envelope-From Mismatch**
```
Sender: l1ko0jy17005odr@oueac.onmicrosoft.com
```
The `Sender:` header (envelope From) uses a different randomly-generated address than the `From:` header. This is characteristic of **bulk phishing infrastructure** — mass-mailing tools use random localparts to avoid blocklists.

### Tools for Header Analysis

```bash
# Paste raw headers into:
https://mxtoolbox.com/EmailHeaders.aspx
https://toolbox.googleapps.com/apps/messageheader/
https://mailheader.org/
```

---

## Step 2 — URL Analysis & Safe Expansion

### URL Found in Email
```
https://t.co/tNeajXlbGt
```

**Why this is dangerous:** `t.co` is Twitter's URL shortener. It completely hides the final destination. The attacker uses it to:
1. Bypass URL reputation filters (t.co itself is trusted)
2. Change the final destination without modifying the email
3. Evade VirusTotal URL scans on the surface URL

### How to Safely Expand a Short URL

**Method 1 — Command line (no browser risk)**
```bash
curl -I --max-redirs 10 -L "https://t.co/tNeajXlbGt" 2>&1 | grep -i location
```

**Method 2 — URLScan.io (safest — takes a screenshot)**
```
https://urlscan.io/search/#page.url:t.co/tNeajXlbGt
```

**Method 3 — CheckShortURL**
```
https://checkshorturl.com
```

**Method 4 — Any.run sandbox**
```
https://app.any.run/  → Submit URL → watch in browser without risk
```

> ❌ **Never** paste the URL directly into a browser on your analyst machine.

---

## Step 3 — VirusTotal Scan

### What VirusTotal Checks
- 90+ antivirus and threat intelligence engines
- URL reputation, domain age, certificate, resolved IPs
- Community scores and comments
- Historical scan data

### How to Use It

**For a URL:**
1. Go to [virustotal.com](https://www.virustotal.com/gui/home/url)
2. Click the **URL** tab
3. Paste: `https://t.co/tNeajXlbGt`
4. Also scan the **expanded final URL**

**For an IP address (from Received headers):**
1. Click the **Search** tab
2. Enter the IP from the `Received:` header

**Using the API (from this repo):**
```python
from tools.phishing_analyzer import virustotal_url_lookup

result = virustotal_url_lookup(
    url="https://t.co/tNeajXlbGt",
    api_key="YOUR_FREE_VT_API_KEY"  # get at virustotal.com/gui/join-us
)
print(result)
# → {"malicious": 14, "suspicious": 3, "harmless": 70, "verdict": "MALICIOUS"}
```

### What to Look For in Results

| Field | Meaning |
|---|---|
| `malicious` count | Number of engines flagging as malicious. >3 = investigate. >10 = high confidence |
| `suspicious` count | Borderline detections — treat as malicious in phishing context |
| Community score | Negative votes = bad reputation |
| `creation_date` | Very recent = suspicious |
| Detected URLs | Other malicious URLs on the same domain |

---

## Step 4 — AbuseIPDB Lookup

### What AbuseIPDB Checks
- Crowdsourced IP abuse reports
- Confidence score (0–100%) that an IP is malicious
- Country, ISP, and usage type
- Historical reports with categories (phishing, spam, hacking)

### How to Use It

**Web:**
```
https://www.abuseipdb.com/check/<IP_ADDRESS>
```

**Using the API (from this repo):**
```python
from tools.phishing_analyzer import abuseipdb_lookup

result = abuseipdb_lookup(
    ip="185.220.101.1",
    api_key="YOUR_FREE_ABUSEIPDB_KEY"  # get at abuseipdb.com/register
)
print(result)
# → {"abuse_confidence_score": 100, "country_code": "DE", "total_reports": 847}
```

### Scoring Guide

| Score | Action |
|---|---|
| 0–24% | Low risk — monitor |
| 25–74% | Suspicious — investigate further |
| 75–100% | Malicious — **block immediately** |

### For This Case
The sending domain is `oueac.onmicrosoft.com` (a Microsoft subdomain), so the IP in the `Received:` header is a **Microsoft data center IP** — it will not flag in AbuseIPDB. This is the whole point of the M365 tenant abuse technique.

> 💡 Focus AbuseIPDB lookups on the **destination URL's server IP** (obtained after expanding the t.co shortener).

---

## Step 5 — WHOIS / IP Lookup

### What to Look For

```
Registration date   → < 30 days old = highly suspicious
Registrar           → Cheap bulk registrars (Namecheap, GoDaddy cheaply) = common in phishing
Registrant country  → Mismatches the claimed brand's country
Privacy protection  → Masked/private WHOIS = evasion technique
Name servers        → Shared cheap hosting = red flag
```

### Tools

```bash
# Web tools:
https://who.is/
https://rdap.org/domain/<domain>
https://whois.domaintools.com/<domain>
https://mxtoolbox.com/SuperTool.aspx?action=mx%3a<domain>

# Command line:
whois oueac.onmicrosoft.com
dig MX oueac.onmicrosoft.com
nslookup oueac.onmicrosoft.com

# Python (pip install python-whois):
import whois
w = whois.whois('oueac.onmicrosoft.com')
print(w.creation_date, w.registrar)
```

### Note for This Case

`oueac.onmicrosoft.com` is a **Microsoft-owned subdomain** — WHOIS will show Microsoft Corporation as the registrant. This is expected and is the attacker's advantage. Instead:

1. Expand the `t.co` short URL to find the final destination domain
2. Run WHOIS on **that** domain
3. A newly-registered domain (< 30 days) with privacy protection is confirmation of phishing

---

## Step 6 — Content & Social Engineering Analysis

### Brand Impersonation

| Indicator | Detail |
|---|---|
| Brand claimed | Norton Antivirus / NortonLifeLock |
| Real domain | `norton.com` |
| Attacker domain | `oueac.onmicrosoft.com` |
| Visual mimicry | Norton name, security terminology, account table layout |

### Psychological Manipulation Tactics

**1. FEAR** — "Your Computer is At Risk", "Protection Has Terminated"  
**2. URGENCY** — "Expires Today 00:00", "Critical Issue That Requires Urgent Action Now!"  
**3. AUTHORITY** — Appears to come from official Norton security team  
**4. SCARCITY** — "89% Renewal Discount" — limited time  
**5. PERSONALISATION** — Recipient's own email shown in the account table  

> This exact combination (Fear + Urgency + Authority + Scarcity) is known as **SCAREWARE** — a classic social engineering technique targeting non-technical users.

### Grammar & Quality Indicators

```
❌ "been activated a special discount to be used on Today"
❌ "Your Protection From Viruses Has terminated" (inconsistent capitalisation)  
❌ Subject line has no punctuation
❌ "susceptible" may be misspelled in body
❌ "Your Computer is at At Risk" (duplicate word)
```

> Poor grammar is still common in phishing. Do not rely on grammar alone — targeted spear-phishing emails are often well-written.

### Attacker Goal

```
Victim clicks "Renew membership"
         ↓
Redirected to fake Norton payment page
         ↓
Enters credit card details
         ↓
Fraudulent charge processed
         ↓
(Some variants) Remote Access Tool (RAT) installed
```

---

## IOC Summary

```json
{
  "emails": [
    "0u4cw6o4bk@oueac.onmicrosoft.com",
    "l1ko0jy17005odr@oueac.onmicrosoft.com"
  ],
  "domains": [
    "oueac.onmicrosoft.com"
  ],
  "urls": [
    "https://t.co/tNeajXlbGt"
  ],
  "subject_keywords": [
    "Antivirus Subscription Has Expired",
    "Renew membership",
    "Norton"
  ],
  "ttp": "T1566.001 — Spearphishing Attachment / Link (MITRE ATT&CK)",
  "technique": "M365 Free Tenant Abuse for SPF/DKIM/DMARC bypass"
}
```

Full IOC file: [`iocs/PHI-2023-1105-001.json`](iocs/PHI-2023-1105-001.json)

---

## Microsoft Sentinel Detection Rule (KQL)

```kql
// Sentinel KQL — Fake Norton Renewal Phishing via M365 Tenant Abuse
EmailEvents
| where SenderFromAddress has_any (
    "@oueac.onmicrosoft.com"
  )
  or (SenderDisplayName has_any ("Norton", "Anti Virus", "Antivirus")
  and SenderFromAddress !endswith "@norton.com")
| where Subject has_any (
    "Subscription Has Expired",
    "Antivirus Subscription",
    "Renew membership",
    "Critical Issue"
  )
| project Timestamp, SenderFromAddress, SenderDisplayName,
          RecipientEmailAddress, Subject, UrlCount
| order by Timestamp desc
```

---

## Recommended Actions

| Priority | Action |
|---|---|
| 🔴 IMMEDIATE | Block sender domain `oueac.onmicrosoft.com` at email gateway |
| 🔴 IMMEDIATE | Block URL `https://t.co/tNeajXlbGt` in Defender / Proofpoint |
| 🔴 IMMEDIATE | Expand short URL and block final destination |
| 🟡 HIGH | Hunt in Sentinel — check if other users received the same email |
| 🟡 HIGH | Check proxy/Defender logs for users who may have clicked the link |
| 🟡 HIGH | Report to Microsoft Abuse: https://msrc.microsoft.com/report/abuse |
| 🟢 MEDIUM | Report to Norton: https://support.norton.com |
| 🟢 MEDIUM | Submit IOCs to PhishTank, URLhaus, VirusTotal |
| 🟢 MEDIUM | Send security awareness email to users about Norton scam wave |
| ℹ️ LOW | Document case in ticketing system with full IOC list |

---

## Tools Reference

| Tool | Use Case | URL |
|---|---|---|
| VirusTotal | URL, domain, IP, hash scanning | virustotal.com |
| AbuseIPDB | IP reputation & abuse history | abuseipdb.com |
| URLScan.io | Safe URL visit + screenshot | urlscan.io |
| URLhaus | Malware URL database (Abuse.ch) | urlhaus.abuse.ch |
| PhishTank | Phishing URL database | phishtank.com |
| MXToolbox | Header analysis, SPF/DKIM/DMARC | mxtoolbox.com/EmailHeaders.aspx |
| WHOIS | Domain registration details | who.is |
| Shodan | IP / server intelligence | shodan.io |
| Any.run | Interactive malware sandbox | app.any.run |
| Google Header Analyzer | Header routing & auth | toolbox.googleapps.com/apps/messageheader |

---

## Project Structure

```
norton-phish-analysis/
│
├── README.md                          ← This file
│
├── tools/
│   ├── phishing_analyzer.py           ← Full analysis script (headers, URLs, IOCs)
│   └── ioc_extractor.py               ← Extract IOCs from raw .eml files
│
├── iocs/
│   └── PHI-2023-1105-001.json         ← Structured IOC file for this case
│
├── screenshots/
│   ├── phishing_email_raw.png         ← Original phishing email screenshot
│   └── analysis_report.html          ← Annotated analysis dashboard
│
└── evidence/
    └── (raw .eml files go here — do not commit live phishing emails publicly)
```

### Running the Tools

```bash
# Clone the repo
git clone https://github.com/yourusername/norton-phish-analysis
cd norton-phish-analysis

# No external dependencies — uses Python stdlib only
python tools/phishing_analyzer.py

# To analyse your own .eml file:
python tools/ioc_extractor.py /path/to/email.eml
```

---

## Skills Demonstrated

- ✅ Email header decomposition (From, Envelope-From, Received chain)
- ✅ SPF / DKIM / DMARC interpretation and bypass detection
- ✅ Microsoft 365 tenant abuse identification
- ✅ URL shortener safe expansion techniques
- ✅ VirusTotal API integration (Python)
- ✅ AbuseIPDB API integration (Python)
- ✅ WHOIS / domain intelligence investigation
- ✅ Social engineering and psychological tactic analysis
- ✅ IOC extraction and structured documentation
- ✅ Microsoft Sentinel KQL detection rule authoring
- ✅ Incident response recommendation playbook
- ✅ MITRE ATT&CK technique mapping (T1566.001)

---

*Maintained by: SOC Analyst Portfolio Project | For educational and portfolio purposes only*
