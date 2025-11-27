import sys
import os
import pyfiglet
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from .utils import console
from .scanner import find_projects, load_lockfile, scan_node_modules, load_package_json
from .checks import check_typosquatting, check_remote_metadata, check_vulnerabilities, fetch_vulnerability_details

def scan_project(project_path):
    console.print(f"\nScanning Project: [bold]{project_path}[/bold]", style="underline")
    
    lockfile_path = os.path.join(project_path, 'package-lock.json')
    node_modules_path = os.path.join(project_path, 'node_modules')
    package_json_path = os.path.join(project_path, 'package.json')
    
    packages = []
    method = ""
    
    if os.path.exists(lockfile_path):
        console.print("  Found package-lock.json. Using exact versions.", style="green")
        packages = load_lockfile(lockfile_path)
        method = "lockfile"
    elif os.path.exists(node_modules_path):
        console.print("  No lockfile. Scanning node_modules for installed versions.", style="yellow")
        packages = scan_node_modules(project_path)
        method = "node_modules"
    elif os.path.exists(package_json_path):
        console.print("  No lockfile or node_modules. Using package.json (approximate versions).", style="yellow")
        packages = load_package_json(package_json_path)
        method = "manifest"
    else:
        console.print("  No dependency information found.", style="red")
        return

    console.print(f"  Found {len(packages)} packages.", style="bold blue")
    
    # Feature C: Typosquatting Detection
    console.print("  Checking for Typosquatting...", style="dim")
    typo_issues = check_typosquatting(packages)
    if typo_issues:
        console.print(f"  [!] Found {len(typo_issues)} potential typosquatting attempts:", style="bold red")
        for issue in typo_issues:
            console.print(f"    - {issue}", style="red")
    else:
        console.print("  [+] Typosquatting checks passed.", style="green")

    # Feature A, B, D: Remote Checks (Integrity, Forensics, Scripts)
    console.print("  Performing Remote Checks (Integrity, Forensics, Scripts)...", style="dim")
    remote_issues = check_remote_metadata(packages, method)
    if remote_issues:
        console.print(f"  [!] Found {len(remote_issues)} issues from remote checks:", style="bold red")
        for issue in remote_issues:
            console.print(f"    - {issue}", style="red")
    else:
        console.print("  [+] Remote checks passed.", style="green")

    vulns = check_vulnerabilities(packages)
    
    if vulns:
        console.print(f"  [!] Found {len(vulns)} vulnerable packages:", style="bold red")
        
        table = Table(title="Vulnerabilities Found", show_header=True, header_style="bold magenta")
        table.add_column("Package", style="cyan")
        table.add_column("Version", style="green")
        table.add_column("ID", style="yellow")
        table.add_column("Summary", style="white")

        for pkg_ver, vuln_list in vulns.items():
            name, version = pkg_ver.split('@')
            for v in vuln_list:
                vuln_id = v['id']
                
                # Fetch full vulnerability details
                vuln_details = fetch_vulnerability_details(vuln_id)
                
                if vuln_details:
                    summary = vuln_details.get('summary')
                    if not summary:
                        # Try database_specific.severity or details
                        summary = vuln_details.get('details', 'No summary')
                        # Truncate long details
                        if len(summary) > 100:
                            summary = summary[:97] + "..."
                else:
                    summary = 'No summary'
                
                table.add_row(name, version, vuln_id, summary)

        
        console.print(table)
    else:
        console.print("  [+] No known vulnerabilities found.", style="bold green")

def main():
    if len(sys.argv) < 2:
        root = "."
    else:
        root = sys.argv[1]
        
    ascii_banner = pyfiglet.figlet_format("ZeroTrustNPM")
    console.print(Text(ascii_banner, style="bold magenta"))
    console.print(Panel(f"Starting ZeroTrustNPM Scanner in: [bold]{os.path.abspath(root)}[/bold]", title="Scanner Info", border_style="blue"))
    
    projects = list(find_projects(root))
    
    if not projects:
        console.print("No NPM projects found.", style="bold red")
        return

    for proj in projects:
        scan_project(proj)

if __name__ == "__main__":
    main()
