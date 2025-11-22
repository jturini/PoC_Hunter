# 🎯 PoC Hunter

> **The CLI Intelligence Tool for Pentesters & Bug Bounty Hunters.**
> Automates the search for CVE exploits across GitHub, ExploitDB, and government databases (NIST/CISA), filtering false positives with a custom Trust Engine.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-Offensive-red?style=for-the-badge)

## 🔥 Features

- **🔍 Multi-Source Search:** Finds exploits in **GitHub** (via API) and **ExploitDB** (Verified CSV).
- **🧠 Vulnerability Intelligence:** Fetches real-time metadata from **NIST NVD** (CVSS Scores, Descriptions).
- **🚨 CISA KEV Integration:** Alerts if a vulnerability is listed in the **Known Exploited Vulnerabilities** catalog (Active Threats).
- **🛡️ Trust Engine:** A heuristic algorithm that filters out fake PoCs, malware, and academic "noise" based on 7 different signals.
- **⚡ Smart Cache:** Caches heavy databases locally (TTL 24h) for instant speeds.
- **📈 Trending:** Shows the latest threats added to the CISA watchlist.
- **📂 Reporting:** Exports search results to Markdown (`report.md`) for documentation.

## 🚀 Installation

```bash
# 1. Clone the repository
git clone [https://github.com/jturini/PoC_Hunter.git](https://github.com/jturini/PoC_Hunter.git)
cd pochunter

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run
python pochunter.py
```

## ⚙️ Configuration (Important)

By default, GitHub allows only **60 requests per hour** for unauthenticated searches. To use PoC Hunter without interruptions (and increase the limit to **5,000 requests/hr**), you must configure a Personal Access Token.

1. Generate a **Classic Token** on GitHub (No permissions needed, just for authentication).
2. Run the tool and use the `token` command:

```text
pochunter > token
Paste GitHub Token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

*✅ The token is stored securely locally in `~/.pochunter/config.json`.*

## 🕹️ Usage

**Interactive Mode (Recommended):**
Simply run `python pochunter.py` to enter the shell.

```text
pochunter > search CVE-2023-44487    # Search for exploits + Info
pochunter > search CVE-2021-44228 py # Filter by language (e.g., Python)
pochunter > info CVE-2017-0144       # Get only vulnerability details
pochunter > trending                 # See CISA KEV latest additions
pochunter > inspect 1                # Analyze why a repo got its score
pochunter > open 1                   # Open the exploit in browser
pochunter > save report.md           # Export results to file
```

**One-Liner Mode:**
You can also run quick searches directly from your terminal:

```bash
python pochunter.py CVE-2023-44487
```

## ⚖️ Legal Disclaimer

**This tool is for educational purposes and authorized security assessments only.**

The author takes no responsibility for any damage caused by the use of this tool. Public repositories often contain malware or fake exploits. **ALWAYS audit the source code** in a sandboxed environment before execution.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.