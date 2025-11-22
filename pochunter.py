#!/usr/bin/env python3
import argparse, os, requests, json, random, sys, csv, webbrowser, time
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt
from rich.panel import Panel

# --- CONFIG & CONSTANTS ---
CONSOLE = Console()
BASE_DIR = Path.home() / ".pochunter"
BASE_DIR.mkdir(exist_ok=True)
FILES = {
    "config": BASE_DIR / "config.json",
    "exploitdb": BASE_DIR / "exploitdb.csv",
    "cisakev": BASE_DIR / "cisa_kev.json"
}
URLS = {
    "exploitdb": "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
    "cisakev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "nist": "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"
}
BANNERS = [
    r"""[bold green]
  ____       _____   _   _             _            
 |  _ \ ___ / ____| | | | |           | |           
 | |_) / _ \ |      | |_| |_   _ _ __ | |_ ___ _ __ 
 |  __/ (_) | |     |  _  | | | | '_ \| __/ _ \ '__|
 |_|   \___/| |____ | | | | |_| | | | | ||  __/ |   
             \_____||_| |_|\__,_|_| |_|\__\___|_|   
      [white]v2.5 - Security Intelligence Engine[/white][/]"""
]


STARTUP_WARNING = """
[bold yellow]⚠️  LEGAL DISCLAIMER & SAFETY WARNING[/bold yellow]

1. [bold]NO WARRANTY:[/bold] This tool is provided "as is". The author takes no responsibility for any damage caused by the use of this tool.
2. [bold]MALWARE RISK:[/bold] Public repositories often contain malware. [red]NEVER execute code blindly.[/red] Always audit the source code in a sandboxed environment (VM).
3. [bold]AUTHORIZATION:[/bold] Use this tool only for educational purposes or authorized security assessments.
"""


LOGIC_EXPLANATION = """
[bold cyan]Scoring Logic (Trust Engine):[/bold cyan]
• [green]+50[/green] Trusted Vendor (Google, Rapid7, etc.)
• [green]+15[/green] Executable Language (Python, C, Go...)
• [green]+10[/green] Valid Exploit Size (3KB - 50MB)
• [green]+Points[/green] Community Stars & Forks (Capped)
• [red]-20[/red] No Language / Academic Noise
• [red]-30[/red] Suspicious Size (<3KB)
• [red]-50[/red] Malware Keywords (fake, crack, password)
"""

# --- TRUST ENGINE ---
class TrustEngine:
    ALLOWLIST_ORGS = ['google', 'projectdiscovery', 'rapid7', 'offensive-security', 'gentilkiwi', 'nmap', 'metasploit', 'trickest']
    SUSPICIOUS_KEYWORDS = ['crack', 'keygen', 'cheat', 'hack tool', 'exe download', 'setup.exe', 'password protected']
    ACADEMIC_KEYWORDS = ['assignment', 'homework', 'course work', 'university', 'tcc', 'class project']

    @staticmethod
    def analyze(repo):
        score = 0
        reasons = []
        
        # 1. AUTHOR AUTHORITY
        owner = repo['owner']['login'].lower()
        if owner in TrustEngine.ALLOWLIST_ORGS:
            score += 50
            reasons.append(f"[green]Trusted Vendor ({owner}) +50[/green]")
        
        # 2. COMMUNITY VALIDATION
        stars = repo['stargazers_count']
        forks = repo['forks_count']
        star_points = min(stars, 50)
        fork_points = min(forks * 2, 30)
        
        if star_points > 0: 
            score += star_points
            reasons.append(f"[green]Community Stars (+{star_points})[/green]")
        if fork_points > 0:
            score += fork_points
            reasons.append(f"[green]Forks (+{fork_points})[/green]")

        # 3. EXECUTABILITY
        valid_langs = ['Python', 'C', 'C++', 'Go', 'Shell', 'Ruby', 'Rust', 'PowerShell']
        lang = repo['language']
        if lang in valid_langs:
            score += 15
            reasons.append(f"[green]Executable Language ({lang}) +15[/green]")
        elif lang is None:
            score -= 20
            reasons.append(f"[red]No Language Detected -20[/red]")

        # 4. SIZE HEURISTICS
        if repo['size'] < 3:
            score -= 30
            reasons.append(f"[red]Suspicious Size (<3KB) -30[/red]")
        elif repo['size'] > 50000:
            score -= 20
            reasons.append(f"[yellow]High Entropy/Size (>50MB) -20[/yellow]")
        else:
            score += 10
            reasons.append(f"[green]Valid Exploit Size +10[/green]")

        # 5. CONTENT ANALYSIS
        desc = (repo['description'] or "").lower()
        found_suspicious = [k for k in TrustEngine.SUSPICIOUS_KEYWORDS if k in desc]
        if found_suspicious:
            score -= 50
            reasons.append(f"[bold red]Malware Indicators ({', '.join(found_suspicious)}) -50[/bold red]")

        found_academic = [k for k in TrustEngine.ACADEMIC_KEYWORDS if k in desc]
        if found_academic:
            score -= 20
            reasons.append(f"[yellow]Academic/Student Repo -20[/yellow]")

        # NORMALIZE
        if score >= 80: confidence = "VERIFIED/HIGH"
        elif score >= 40: confidence = "REVIEW NEEDED"
        else: confidence = "LOW/RISK"

        return score, confidence, reasons

class DatabaseManager:
    @staticmethod
    def needs_update(filepath):
        if not filepath.exists(): return True
        return (time.time() - os.path.getmtime(filepath)) > 86400

    @staticmethod
    def update(force=False):
        for key, url in [('exploitdb', URLS['exploitdb']), ('cisakev', URLS['cisakev'])]:
            fpath = FILES[key]
            if force or DatabaseManager.needs_update(fpath):
                try:
                    CONSOLE.print(f"[dim]Updating {key.upper()}...[/dim]")
                    r = requests.get(url, timeout=30)
                    if r.status_code == 200:
                        with open(fpath, 'wb') as f: f.write(r.content)
                        CONSOLE.print(f"[green]✔ {key.upper()} updated.[/green]")
                except: CONSOLE.print(f"[red]Failed to update {key}.[/red]")

    @staticmethod
    def check_cisa(cve_id):
        if not FILES['cisakev'].exists(): return False
        try:
            with open(FILES['cisakev'], 'r') as f:
                data = json.load(f)
                return any(v['cveID'] == cve_id for v in data.get('vulnerabilities', []))
        except: return False

    @staticmethod
    def search_exploitdb(cve_id):
        results = []
        if not FILES['exploitdb'].exists(): return []
        try:
            with open(FILES['exploitdb'], 'r', encoding='utf-8') as f:
                for row in csv.DictReader(f):
                    if row['codes'] and cve_id in row['codes']:
                        results.append({
                            "name": row['description'], "stars": "Verified",
                            "language": row['type'], "html_url": f"https://www.exploit-db.com/exploits/{row['id']}",
                            "source": "ExploitDB", "score": 100,
                            "confidence": "OFFICIAL", "reasons": ["[green]Sourced from ExploitDB[/green]"]
                        })
        except: pass
        return results

class PoCHunter:
    def __init__(self):
        self.last_results = []
        self.config = self._load_config()

    def _load_config(self):
        if FILES['config'].exists():
            try: return json.loads(FILES['config'].read_text())
            except: pass
        return {}

    def _get_headers(self):
        token = os.getenv("GITHUB_TOKEN") or self.config.get("GITHUB_TOKEN")
        headers = {"Accept": "application/vnd.github.v3+json"}
        if token: headers["Authorization"] = f"token {token}"
        return headers

    def cmd_token(self, args):
        token = Prompt.ask("Paste GitHub Token")
        with open(FILES['config'], "w") as f: json.dump({"GITHUB_TOKEN": token}, f)
        self.config = {"GITHUB_TOKEN": token}
        CONSOLE.print("[green]✔ Token saved![/green]")

    def cmd_update(self, args):
        CONSOLE.print("[bold yellow]Forcing update...[/bold yellow]")
        DatabaseManager.update(force=True)

    def cmd_disclaimer(self, args):
        CONSOLE.print(Panel(LOGIC_EXPLANATION, title="ℹ️  About Scoring & Safety", border_style="cyan"))

    def cmd_trending(self, args):
        if not FILES['cisakev'].exists(): return CONSOLE.print("[red]Database missing.[/red]")
        try:
            with open(FILES['cisakev'], 'r') as f:
                vulns = json.load(f).get('vulnerabilities', [])
                vulns.sort(key=lambda x: x['dateAdded'], reverse=True)
                table = Table(title="🔥 CISA KEV Trending")
                table.add_column("Date", style="cyan"); table.add_column("CVE", style="white")
                table.add_column("Name", style="magenta")
                for v in vulns[:10]:
                    table.add_row(v['dateAdded'], v['cveID'], v['vulnerabilityName'][:60])
                CONSOLE.print(table)
        except Exception as e: CONSOLE.print(f"[red]Error: {e}[/red]")

    def cmd_open(self, args):
        if not args or not self.last_results: return CONSOLE.print("[red]Usage: open <#> (after a search)[/red]")
        try:
            idx = int(args[0]) - 1
            if 0 <= idx < len(self.last_results): webbrowser.open(self.last_results[idx]['html_url'])
            else: CONSOLE.print("[red]Invalid number.[/red]")
        except: CONSOLE.print("[red]Invalid input.[/red]")

    def cmd_inspect(self, args):
        if not args or not self.last_results: return CONSOLE.print("[red]Usage: inspect <#> (to see score reasons)[/red]")
        try:
            idx = int(args[0]) - 1
            if 0 <= idx < len(self.last_results):
                item = self.last_results[idx]
                reasons_str = "\n".join([f"• {r}" for r in item['reasons']])
                content = f"""
[bold white]Repository:[/bold white] {item['name']}
[bold white]URL:[/bold white] {item['html_url']}
[bold white]Score:[/bold white] {item['score']}
[bold white]Confidence Bucket:[/bold white] {item['confidence']}

[bold underline cyan]Analysis Log:[/bold underline cyan]
{reasons_str}

[dim]Desc: {item.get('description', 'No description')}[/dim]
                """
                border_color = "green" if item['score'] > 80 else "yellow" if item['score'] > 40 else "red"
                CONSOLE.print(Panel(content, title="🔍 Deep Inspection", border_style=border_color))
            else: CONSOLE.print("[red]Invalid number.[/red]")
        except Exception as e: CONSOLE.print(f"[red]Error: {e}[/red]")

    def cmd_save(self, args):
        if not self.last_results: return CONSOLE.print("[red]No results to save.[/red]")
        filename = args[0] if args else "report.md"
        if not filename.endswith((".md", ".txt")): filename += ".md"
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"# PoC Hunter Report\n**Date:** {datetime.now()}\n\n")
                f.write("| Source | Score | Bucket | Name | Stars | Link |\n|---|---|---|---|---|---|\n")
                for item in self.last_results:
                    f.write(f"| {item['source']} | {item['score']} | {item['confidence']} | {item['name'].replace('|','-')} | {item['stars']} | {item['html_url']} |\n")
            CONSOLE.print(f"[green]✔ Saved to {filename}[/green]")
        except Exception as e: CONSOLE.print(f"[red]Error: {e}[/red]")

    def fetch_info(self, cve_id):
        kev_alert = "\n[bold white on red] 🚨 CISA KEV LISTED [/]" if DatabaseManager.check_cisa(cve_id) else ""
        try:
            r = requests.get(URLS['nist'].format(cve_id), timeout=10)
            if r.status_code != 200: return CONSOLE.print(f"[red]NIST Error: {r.status_code}[/red]")
            data = r.json()
            if not data.get("vulnerabilities"): return CONSOLE.print("[yellow]NIST: No details found.[/yellow]")
            item = data["vulnerabilities"][0]["cve"]
            desc = next((d['value'] for d in item.get('descriptions', []) if d['lang'] == 'en'), "No description")
            metrics = item.get("metrics", {})
            cvss = 0.0
            for v in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if v in metrics:
                    cvss = metrics[v][0]["cvssData"]["baseScore"]
                    break
            color = "red" if cvss >= 9 else "orange1" if cvss >= 7 else "yellow" if cvss >= 4 else "green"
            content = f"[bold]ID:[/bold] {cve_id}\n[bold]CVSS:[/bold] [{color}]{cvss}[/]{kev_alert}\n\n[bold]Desc:[/bold]\n{desc}"
            CONSOLE.print(Panel(content, title=f"[{color}]Intelligence[/]", expand=False))
        except Exception as e: CONSOLE.print(f"[red]Info Error: {e}[/red]")

    def fetch_github(self, cve_id):
        try:
            r = requests.get(f"https://api.github.com/search/repositories?q={cve_id}&sort=updated", headers=self._get_headers())
            if r.status_code == 200:
                items = []
                for i in r.json().get('items', []):
                    score, confidence, reasons = TrustEngine.analyze(i)
                    items.append({
                        "name": i['name'], "stars": str(i['stargazers_count']),
                        "language": i['language'] or "N/A", "html_url": i['html_url'],
                        "description": i['description'], "source": "GitHub",
                        "score": score, "confidence": confidence, "reasons": reasons
                    })
                return items
            elif r.status_code == 403: CONSOLE.print("[red]GitHub Rate Limit![/red]")
        except: pass
        return []

    def cmd_search(self, args, info_only=False):
        if not args: return CONSOLE.print("[red]Usage: search <CVE> [lang][/red]")
        cve = args[0].upper()
        lang_filter = args[1].lower() if len(args) > 1 else None
        
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=True) as p:
            p.add_task("Fetching Info...", total=None)
            self.fetch_info(cve)
            if info_only: return

            p.add_task("Hunting Exploits...", total=None)
            results = DatabaseManager.search_exploitdb(cve) + self.fetch_github(cve)

        if lang_filter:
            results = [r for r in results if lang_filter in r['language'].lower()]

        results.sort(key=lambda x: x['score'], reverse=True)
        self.last_results = results

        if not results: return CONSOLE.print(f"[yellow]No exploits found (Filter: {lang_filter or 'None'}).[/yellow]")
        
        table = Table(title=f"Exploits for {cve}")
        table.add_column("#", style="white"); table.add_column("Bucket", style="bold"); table.add_column("Score", style="cyan")
        table.add_column("Name", style="magenta"); table.add_column("Lang", style="yellow"); table.add_column("Link", style="blue", overflow="fold")

        for i, r in enumerate(results[:15], 1):
            b_color = "green" if "VERIFIED" in r['confidence'] or "OFFICIAL" in r['confidence'] else "yellow" if "REVIEW" in r['confidence'] else "red"
            table.add_row(str(i), f"[{b_color}]{r['confidence']}[/]", str(r['score']), r['name'][:30], r['language'], r['html_url'])
        
        CONSOLE.print(table)
        CONSOLE.print("[dim]Tip: Use 'inspect <#>' to see why a repo got its score.[/dim]")

    def run(self):
        CONSOLE.print(random.choice(BANNERS))
        
        CONSOLE.print(Panel(STARTUP_WARNING, border_style="yellow"))
        DatabaseManager.update()
        
        commands = {
            "search": self.cmd_search, "info": lambda x: self.cmd_search(x, info_only=True),
            "open": self.cmd_open, "save": self.cmd_save, "token": self.cmd_token,
            "trending": self.cmd_trending, "update": self.cmd_update, 
            "inspect": self.cmd_inspect, "disclaimer": self.cmd_disclaimer,
            "help": lambda x: CONSOLE.print("cmds: search <CVE> [lang], info, inspect, open, save, trending, update, token, disclaimer, exit")
        }
        while True:
            try:
                user_input = Prompt.ask("[bold underline green]pochunter[/] [bold white]>[/]").strip()
                if not user_input: continue
                parts = user_input.split()
                cmd, args = parts[0].lower(), parts[1:]
                if cmd in ["exit", "quit"]: break
                if cmd in commands: commands[cmd](args)
                else: CONSOLE.print("[red]Unknown command.[/red]")
            except KeyboardInterrupt:
                CONSOLE.print("\n[red]Exiting...[/red]")
                break
            except Exception as e: CONSOLE.print(f"[red]Error: {e}[/red]")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cve", nargs="?")
    args = parser.parse_args()
    app = PoCHunter()
    if args.cve: app.cmd_search([args.cve])
    else: app.run()

if __name__ == "__main__":
    main()