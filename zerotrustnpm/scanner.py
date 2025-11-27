import os
import json
from .utils import console

def find_projects(root_dir):
    """
    Recursively finds directories that look like NPM projects.
    Yields paths to directories containing package.json or node_modules.
    """
    for dirpath, dirnames, filenames in os.walk(root_dir):
        if 'node_modules' in dirnames:
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
        
        if 'packages' in data:
            for pkg_path, details in data['packages'].items():
                if pkg_path == "": continue # Skip root
                
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
    """
    try:
        with open(manifest_path, 'r') as f:
            data = json.load(f)
        
        packages = []
        deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
        
        for name, version_range in deps.items():
            # Naive cleanup to get something checkable
            clean_version = version_range.replace('^', '').replace('~', '')
            if clean_version and not any(c in clean_version for c in ['/', ':', '*']):
                 packages.append({"name": name, "version": clean_version})
        
        return packages
    except Exception as e:
        console.print(f"Error loading package.json {manifest_path}: {e}", style="red")
        return []
