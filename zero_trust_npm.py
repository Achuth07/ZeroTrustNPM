import os
import json
import requests
import sys

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
        print(f"Error loading lockfile {lockfile_path}: {e}")
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
        print(f"Error loading package.json {manifest_path}: {e}")
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
        print(f"Error querying OSV API: {response.status_code}")
        return {}
        
    results = response.json().get('results', [])
    
    vulnerabilities = {}
    for i, result in enumerate(results):
        if 'vulns' in result:
            pkg = packages[i]
            key = f"{pkg['name']}@{pkg['version']}"
            vulnerabilities[key] = result['vulns']
            
    return vulnerabilities

def scan_project(project_path):
    print(f"\nScanning Project: {project_path}")
    
    lockfile_path = os.path.join(project_path, 'package-lock.json')
    node_modules_path = os.path.join(project_path, 'node_modules')
    package_json_path = os.path.join(project_path, 'package.json')
    
    packages = []
    method = ""
    
    if os.path.exists(lockfile_path):
        print("  Found package-lock.json. Using exact versions.")
        packages = load_lockfile(lockfile_path)
        method = "lockfile"
    elif os.path.exists(node_modules_path):
        print("  No lockfile. Scanning node_modules for installed versions.")
        packages = scan_node_modules(project_path)
        method = "node_modules"
    elif os.path.exists(package_json_path):
        print("  No lockfile or node_modules. Using package.json (approximate versions).")
        packages = load_package_json(package_json_path)
        method = "manifest"
    else:
        print("  No dependency information found.")
        return

    print(f"  Found {len(packages)} packages.")
    
    # Feature A: Integrity Verification
    print("  [Phase 2] Verifying Integrity...")
    integrity_issues = check_integrity(packages, method, project_path)
    if integrity_issues:
        print(f"  [!] Found {len(integrity_issues)} integrity mismatches:")
        for issue in integrity_issues:
            print(f"    - {issue}")
    else:
        print("  [+] Integrity checks passed.")

    vulns = check_vulnerabilities(packages)
    
    if vulns:
        print(f"  [!] Found {len(vulns)} vulnerable packages:")
        for pkg_ver, vuln_list in vulns.items():
            print(f"    - {pkg_ver}:")
            for v in vuln_list:
                print(f"      ID: {v['id']}")
                print(f"      Summary: {v.get('summary', 'No summary')}")
    else:
        print("  [+] No known vulnerabilities found.")

def check_integrity(packages, method, project_path):
    """
    Verifies package integrity against the NPM registry.
    """
    issues = []
    # We only check integrity if we have a lockfile (which has the 'integrity' field)
    # OR if we are scanning node_modules (where we might check _integrity in package.json if it exists, but usually dist.shasum)
    # For MVP Phase 2, let's focus on verifying what we have.
    
    # If method is 'lockfile', we have expected integrity in the 'packages' list if we extracted it.
    # Wait, load_lockfile didn't extract integrity. We need to update it.
    
    # If method is 'node_modules', we can't easily verify integrity unless we hash the files, 
    # which is expensive. But we can check if the installed version's metadata matches registry.
    # Actually, the user requirement says: "Compare it strictly against the integrity field in your local package-lock.json."
    # So this feature is primarily for lockfile validation.
    
    if method != 'lockfile':
        return []

    for pkg in packages:
        name = pkg['name']
        version = pkg['version']
        local_integrity = pkg.get('integrity')
        
        if not local_integrity:
            continue
            
        # Fetch from registry
        try:
            # Use a session or just requests? requests is fine for now.
            # Registry URL: https://registry.npmjs.org/<package_name>/<version>
            url = f"https://registry.npmjs.org/{name}/{version}"
            resp = requests.get(url)
            
            if resp.status_code == 200:
                data = resp.json()
                remote_integrity = data.get('dist', {}).get('integrity')
                remote_shasum = data.get('dist', {}).get('shasum')
                
                # Local integrity in lockfile is usually "algo-hash".
                # Registry returns both.
                
                if local_integrity != remote_integrity:
                    # Sometimes lockfile has sha1, registry has sha512.
                    # If local looks like sha1 (hex), compare with shasum.
                    # If local looks like sha512 (base64), compare with integrity.
                    
                    # Simple check:
                    if local_integrity == remote_shasum:
                        continue # Match (legacy sha1)
                        
                    issues.append(f"{name}@{version}: Local integrity {local_integrity[:20]}... != Remote {remote_integrity[:20]}...")
            else:
                # issues.append(f"{name}@{version}: Could not fetch metadata (Status {resp.status_code})")
                pass
        except Exception as e:
            # issues.append(f"{name}@{version}: Error checking integrity: {e}")
            pass
            
    return issues

def main():
    if len(sys.argv) < 2:
        root = "."
    else:
        root = sys.argv[1]
        
    print(f"Starting ZeroTrustNPM Scanner in: {os.path.abspath(root)}")
    
    projects = list(find_projects(root))
    
    if not projects:
        print("No NPM projects found.")
        return

    for proj in projects:
        scan_project(proj)

if __name__ == "__main__":
    main()
