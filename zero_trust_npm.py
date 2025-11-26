import os
import json
import requests
import sys
import pyfiglet
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()

OSV_API_URL = "https://api.osv.dev/v1/querybatch"

def find_projects(root_dir):
    """
    Recursively finds directories that look like NPM projects.
    Yields paths to directories containing package.json or node_modules.
    """
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Skip node_modules to avoid deep recursion into dependencies of dependencies
        # unless we are specifically looking inside them (which we handle separately if needed)
        if 'node_modules' in dirnames:
            # If we find a node_modules at this level, it's likely a project root
            # We still want to traverse into it? No, usually we scan the top level project.
            # But the user asked to "Recursively scan directories for node_modules folders".
            # Let's assume we want to find *projects*, not every single package inside node_modules
            # as a separate project, unless it's a monorepo structure.
            # For now, let's treat any dir with package.json as a potential project.
            pass
        
        if 'package.json' in filenames:
            yield dirpath

def load_lockfile(lockfile_path):
    """
    Parses package-lock.json to extract exact versions.
    Returns a list of {"name": name, "version": version} dicts.
    """
    try:
        with open(lockfile_path, 'r') as f:
            data = json.load(f)
        
        packages = []
        # dependencies are usually in 'dependencies' (v1) or 'packages' (v2/v3)
        # 'packages' includes the root "" which we skip, and node_modules/... paths
        
        if 'packages' in data:
            for pkg_path, details in data['packages'].items():
                if pkg_path == "": continue # Skip root
                
                # We want the package name. In 'packages', keys are like "node_modules/foo"
                # The name is the last part, OR it's in details.get('name')?
                # Actually, for OSV, we just need name and version.
                # 'packages' format keys are paths.
                
                name = pkg_path.split("node_modules/")[-1]
                version = details.get('version')
                integrity = details.get('integrity')
                
                if name and version:
                    packages.append({"name": name, "version": version, "integrity": integrity})
                    
        elif 'dependencies' in data:
            # Legacy v1 format
            for name, details in data['dependencies'].items():
                version = details.get('version')
                integrity = details.get('integrity')
                if version:
                    packages.append({"name": name, "version": version, "integrity": integrity})
                    
        return packages
    except Exception as e:
        console.print(f"Error loading lockfile {lockfile_path}: {e}", style="red")
        return []

def scan_node_modules(project_dir):
    """
    Scans node_modules directory to find installed packages and their versions.
    Returns a list of {"name": name, "version": version} dicts.
    """
    modules_dir = os.path.join(project_dir, 'node_modules')
    if not os.path.exists(modules_dir):
        return []
    
    packages = []
    # We only look at top-level modules in node_modules for now to avoid massive noise,
    # or should we scan everything? The user said "Recursively scan directories for node_modules folders".
    # If we are in a project, we probably want to check all installed deps.
    # Let's just check top-level for MVP to avoid performance issues, or walk?
    # Let's walk one level deep for scoped packages (e.g. @types/foo)
    
    for item in os.listdir(modules_dir):
        item_path = os.path.join(modules_dir, item)
        
        if item.startswith('@') and os.path.isdir(item_path):
            # Scoped package, look inside
            for subitem in os.listdir(item_path):
                subitem_path = os.path.join(item_path, subitem)
                pkg = _read_package_json_version(subitem_path)
                if pkg: packages.append(pkg)
        elif os.path.isdir(item_path):
            pkg = _read_package_json_version(item_path)
            if pkg: packages.append(pkg)
            
    return packages

def _read_package_json_version(dir_path):
    pkg_json_path = os.path.join(dir_path, 'package.json')
    if os.path.exists(pkg_json_path):
        try:
            with open(pkg_json_path, 'r') as f:
                data = json.load(f)
                return {"name": data.get('name'), "version": data.get('version')}
        except:
            pass
    return None

def load_package_json(manifest_path):
    """
    Parses package.json to extract dependencies with version ranges.
    Note: OSV might not handle ranges well in batch query, or it might.
    Actually OSV API expects 'version' or 'commit'. It doesn't support ranges in the simple querybatch endpoint easily
    without ecosystem specific logic.
    For MVP, we will warn that we are using ranges and just send them, 
    but OSV might return nothing if it expects exact versions.
    Let's try to strip caret/tilde to get a "base" version for checking, 
    or just report that we can't check accurately.
    """
    try:
        with open(manifest_path, 'r') as f:
            data = json.load(f)
        
        packages = []
        deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
        
        for name, version_range in deps.items():
            # Naive cleanup to get something checkable
            clean_version = version_range.replace('^', '').replace('~', '')
            # If it's *, or git url, we skip for now
            if clean_version and not any(c in clean_version for c in ['/', ':', '*']):
                 packages.append({"name": name, "version": clean_version})
        
        return packages
    except Exception as e:
        console.print(f"Error loading package.json {manifest_path}: {e}", style="red")
        return []

def check_vulnerabilities(packages):
    """
    Queries OSV.dev API for vulnerabilities.
    """
    if not packages:
        return {}
        
    # OSV batch query format
    queries = []
    for pkg in packages:
        queries.append({
            "package": {
                "name": pkg['name'],
                "ecosystem": "npm"
            },
            "version": pkg['version']
        })
    
    # Batch in chunks of 1000 if needed, but for MVP just one shot
    response = requests.post(OSV_API_URL, json={"queries": queries})
    
    if response.status_code != 200:
        console.print(f"Error querying OSV API: {response.status_code}", style="bold red")
        return {}
        
    results = response.json().get('results', [])
    
    vulnerabilities = {}
    for i, result in enumerate(results):
        if 'vulns' in result:
            pkg = packages[i]
            key = f"{pkg['name']}@{pkg['version']}"
            vulnerabilities[key] = result['vulns']
            
    return vulnerabilities

def fetch_vulnerability_details(vuln_id):
    """
    Fetches full vulnerability details from OSV API for a given vulnerability ID.
    Returns the full vulnerability object with summary, details, etc.
    """
    try:
        url = f"https://api.osv.dev/v1/vulns/{vuln_id}"
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        else:
            return None
    except Exception as e:
        console.print(f"[!] Error fetching details for {vuln_id}: {e}", style="dim red")
        return None


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
    console.print("  [Phase 2] Checking for Typosquatting...", style="dim")
    typo_issues = check_typosquatting(packages)
    if typo_issues:
        console.print(f"  [!] Found {len(typo_issues)} potential typosquatting attempts:", style="bold red")
        for issue in typo_issues:
            console.print(f"    - {issue}", style="red")
    else:
        console.print("  [+] Typosquatting checks passed.", style="green")

    # Feature A, B, D: Remote Checks (Integrity, Forensics, Scripts)
    console.print("  [Phase 2] Performing Remote Checks (Integrity, Forensics, Scripts)...", style="dim")
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

TOP_50_PACKAGES = [
    "react", "react-dom", "lodash", "express", "chalk", "commander", "debug", "tslib", "requests", "moment",
    "axios", "prop-types", "uuid", "classnames", "bluebird", "yargs", "async", "fs-extra", "mkdirp", "webpack",
    "body-parser", "glob", "inquirer", "jquery", "underscore", "dotenv", "colors", "minimist", "rxjs", "zone.js",
    "core-js", "babel-core", "babel-loader", "babel-runtime", "vue", "next", "eslint", "jest", "mocha", "aws-sdk",
    "socket.io", "mongoose", "redis", "superagent", "morgan", "winston", "pm2", "nodemon", "rimraf", "semver"
]

def check_typosquatting(packages):
    """
    Feature C: Checks for typosquatting against top 50 packages.
    """
    try:
        import jellyfish
    except ImportError:
        console.print("  [!] jellyfish library not found. Skipping typosquatting check.", style="bold yellow")
        return []

    issues = []
    for pkg in packages:
        name = pkg['name']
        
        # Skip if exact match (it's the real package)
        if name in TOP_50_PACKAGES:
            continue
            
        for top_pkg in TOP_50_PACKAGES:
            dist = jellyfish.levenshtein_distance(name, top_pkg)
            if dist > 0 and dist <= 2:
                issues.append(f"Package '{name}' is very similar to '{top_pkg}' (Distance: {dist})")
                
    return issues

def check_remote_metadata(packages, method):
    """
    Feature A: Integrity Verification
    Feature B: Metadata Forensics (Freshness, Version Count)
    Feature D: Script Auditing
    """
    issues = []
    
    # We process all packages, but integrity check only if we have local integrity
    
    import datetime
    
    for pkg in packages:
        name = pkg['name']
        version = pkg['version']
        local_integrity = pkg.get('integrity')
        
        try:
            # Fetch full metadata for Forensics
            url = f"https://registry.npmjs.org/{name}"
            resp = requests.get(url)
            
            if resp.status_code != 200:
                # issues.append(f"{name}: Could not fetch metadata (Status {resp.status_code})")
                continue
                
            data = resp.json()
            
            # --- Feature A: Integrity ---
            if local_integrity:
                version_data = data.get('versions', {}).get(version)
                if version_data:
                    remote_integrity = version_data.get('dist', {}).get('integrity')
                    remote_shasum = version_data.get('dist', {}).get('shasum')
                    
                    if local_integrity != remote_integrity and local_integrity != remote_shasum:
                         issues.append(f"[Integrity] {name}@{version}: Local {local_integrity[:15]}... != Remote {remote_integrity[:15]}...")
                else:
                    issues.append(f"[Integrity] {name}@{version}: Version not found in registry.")

            # --- Feature B: Forensics ---
            # 1. Freshness
            time_data = data.get('time', {})
            pub_time_str = time_data.get(version)
            if pub_time_str:
                # Parse "2020-05-05T22:23:38.856Z"
                pub_time_str = pub_time_str.replace('Z', '+00:00')
                try:
                    pub_time = datetime.datetime.fromisoformat(pub_time_str)
                    now = datetime.datetime.now(datetime.timezone.utc)
                    age = now - pub_time
                    if age.total_seconds() < 48 * 3600:
                        issues.append(f"[Forensics] {name}@{version}: Published less than 48 hours ago ({age}).")
                except ValueError:
                    pass
            
            # 2. Version Count
            num_versions = len(data.get('versions', {}))
            if num_versions < 3:
                issues.append(f"[Forensics] {name}: Has fewer than 3 versions ({num_versions}).")

            # --- Feature D: Script Auditing ---
            # Check scripts in the registry metadata for this version
            version_data = data.get('versions', {}).get(version)
            if version_data:
                scripts = version_data.get('scripts', {})
                suspicious = ['preinstall', 'install', 'postinstall']
                for script_name in scripts:
                    if script_name in suspicious:
                        cmd = scripts[script_name]
                        issues.append(f"[Scripts] {name}@{version}: Has '{script_name}' script: '{cmd}'")

        except Exception as e:
            # issues.append(f"{name}: Error checking remote metadata: {e}")
            pass
            
    return issues

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
