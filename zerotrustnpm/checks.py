import requests
import datetime
import jellyfish
from .utils import console, OSV_API_URL, TOP_50_PACKAGES

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

def check_typosquatting(packages):
    """
    Feature C: Checks for typosquatting against top 50 packages.
    """
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
    
    for pkg in packages:
        name = pkg['name']
        version = pkg['version']
        local_integrity = pkg.get('integrity')
        
        try:
            # Fetch full metadata for Forensics
            url = f"https://registry.npmjs.org/{name}"
            resp = requests.get(url)
            
            if resp.status_code != 200:
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
            pass
            
    return issues
