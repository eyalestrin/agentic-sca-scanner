#!/usr/bin/env python3
"""
Agentic Software Composition Analysis (SCA) Scanner
Recursively scans target directories for dependencies, checks them against open-source
vulnerability databases (OSV.dev API), and generates detailed vulnerability & remediation reports.
"""

import os
import json
import argparse
import urllib.request
import urllib.error
import re
from pathlib import Path
from typing import Dict, List, Any, Optional

OSV_API_URL = "https://api.osv.dev/v1/query"

class DependencyScanner:
    def __init__(self, root_dir: str):
        self.root_dir = Path(root_dir).resolve()
        self.dependencies: List[Dict[str, Any]] = []

    def scan_directory(self) -> List[Dict[str, Any]]:
        print(f"[*] Starting directory scan at: {self.root_dir}")
        for root, _, files in os.walk(self.root_dir):
            root_path = Path(root)
            # Skip common hidden/build dirs
            if any(part.startswith('.') or part in ('node_modules', 'venv', '__pycache__', 'dist', 'build') for part in root_path.parts):
                continue

            for file in files:
                file_path = root_path / file
                if file == 'package.json':
                    self._parse_package_json(file_path)
                elif file == 'package-lock.json':
                    self._parse_package_lock(file_path)
                elif file == 'requirements.txt':
                    self._parse_requirements_txt(file_path)
                elif file == 'Pipfile.lock':
                    self._parse_pipfile_lock(file_path)
                elif file == 'go.mod':
                    self._parse_go_mod(file_path)

        return self.dependencies

    def _parse_package_json(self, path: Path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
                for name, version_str in deps.items():
                    clean_ver = re.sub(r'[^0-9.]', '', version_str)
                    if clean_ver:
                        self.dependencies.append({
                            'name': name,
                            'version': clean_ver,
                            'ecosystem': 'npm',
                            'type': 'Direct',
                            'manifest': str(path.relative_to(self.root_dir)),
                            'parent': None
                        })
        except Exception as e:
            print(f"[!] Warning: Failed to parse {path}: {e}")

    def _parse_package_lock(self, path: Path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                packages = data.get('packages', {})
                for pkg_path, pkg_info in packages.items():
                    if not pkg_path:  # Root package
                        continue
                    name = pkg_info.get('name') or pkg_path.split('node_modules/')[-1]
                    version = pkg_info.get('version')
                    if name and version:
                        is_direct = not ('node_modules' in pkg_path and pkg_path.count('node_modules') > 1)
                        self.dependencies.append({
                            'name': name,
                            'version': version,
                            'ecosystem': 'npm',
                            'type': 'Direct' if is_direct else 'Transitive',
                            'manifest': str(path.relative_to(self.root_dir)),
                            'parent': 'Root Package' if is_direct else 'Parent Module'
                        })
        except Exception as e:
            print(f"[!] Warning: Failed to parse {path}: {e}")

    def _parse_requirements_txt(self, path: Path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        match = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*==\s*([a-zA-Z0-9_\-\.]+)', line)
                        if match:
                            self.dependencies.append({
                                'name': match.group(1),
                                'version': match.group(2),
                                'ecosystem': 'PyPI',
                                'type': 'Direct',
                                'manifest': str(path.relative_to(self.root_dir)),
                                'parent': None
                            })
        except Exception as e:
            print(f"[!] Warning: Failed to parse {path}: {e}")

    def _parse_pipfile_lock(self, path: Path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                default_deps = data.get('default', {})
                for name, info in default_deps.items():
                    version = info.get('version', '').replace('==', '')
                    if version:
                        self.dependencies.append({
                            'name': name,
                            'version': version,
                            'ecosystem': 'PyPI',
                            'type': 'Transitive',
                            'manifest': str(path.relative_to(self.root_dir)),
                            'parent': 'Pipfile Dependencies'
                        })
        except Exception as e:
            print(f"[!] Warning: Failed to parse {path}: {e}")

    def _parse_go_mod(self, path: Path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('require') or re.match(r'^[a-zA-Z0-9\.\/_\-]+\s+v[0-9]', line):
                        parts = line.replace('require', '').strip().split()
                        if len(parts) >= 2:
                            pkg_name = parts[0]
                            version = parts[1].lstrip('v')
                            is_transitive = '// indirect' in line
                            self.dependencies.append({
                                'name': pkg_name,
                                'version': version,
                                'ecosystem': 'Go',
                                'type': 'Transitive' if is_transitive else 'Direct',
                                'manifest': str(path.relative_to(self.root_dir)),
                                'parent': 'go.mod parent' if is_transitive else None
                            })
        except Exception as e:
            print(f"[!] Warning: Failed to parse {path}: {e}")


class OSVAuditor:
    @staticmethod
    def check_vulnerability(pkg: Dict[str, Any]) -> Dict[str, Any]:
        payload = {
            "package": {
                "name": pkg['name'],
                "ecosystem": pkg['ecosystem']
            },
            "version": pkg['version']
        }
        
        req = urllib.request.Request(
            OSV_API_URL,
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )

        vulnerabilities = []
        try:
            with urllib.request.urlopen(req) as response:
                if response.status == 200:
                    res_data = json.loads(response.read().decode('utf-8'))
                    vulns = res_data.get('vulns', [])
                    for v in vulns:
                        fixed_versions = []
                        for affected in v.get('affected', []):
                            for ranges in affected.get('ranges', []):
                                for event in ranges.get('events', []):
                                    if 'fixed' in event:
                                        fixed_versions.append(event['fixed'])
                        
                        vulnerabilities.append({
                            'id': v.get('id'),
                            'summary': v.get('summary', 'No summary available'),
                            'details': v.get('details', ''),
                            'references': [r.get('url') for r in v.get('references', []) if r.get('url')],
                            'fixed_versions': fixed_versions
                        })
        except urllib.error.HTTPError as e:
            pass
        except Exception as e:
            print(f"[!] API Error scanning {pkg['name']}: {e}")

        pkg_result = dict(pkg)
        pkg_result['vulnerabilities'] = vulnerabilities
        return pkg_result


def generate_report(results: List[Dict[str, Any]], output_file: str):
    total_packages = len(results)
    vulnerable_packages = [r for r in results if r['vulnerabilities']]
    total_vulns = sum(len(r['vulnerabilities']) for r in vulnerable_packages)
    unpatched_count = 0

    for pkg in vulnerable_packages:
        for v in pkg['vulnerabilities']:
            if not v['fixed_versions']:
                unpatched_count += 1

    report = []
    report.append("# Software Composition Analysis (SCA) & Vulnerability Report\n")
    report.append("## Executive Summary\n")
    report.append(f"- **Total Packages Identified:** {total_packages}")
    report.append(f"- **Vulnerable Packages:** {len(vulnerable_packages)}")
    report.append(f"- **Total Identified Vulnerabilities:** {total_vulns}")
    report.append(f"- **Packages with No Available Upstream Patch:** {unpatched_count}\n")

    report.append("| Package Name | Version | Ecosystem | Type | Vulnerabilities | Safe Upgrade Path |")
    report.append("| :--- | :--- | :--- | :--- | :--- | :--- |")

    for pkg in results:
        vuln_str = "None"
        fix_str = "N/A (Up to date / Clean)"

        if pkg['vulnerabilities']:
            vuln_ids = [v['id'] for v in pkg['vulnerabilities']]
            vuln_str = "<br>".join(vuln_ids)

            all_fixes = []
            for v in pkg['vulnerabilities']:
                if v['fixed_versions']:
                    all_fixes.extend(v['fixed_versions'])
            
            if all_fixes:
                fix_str = f"Upgrade to `{all_fixes[0]}` or higher"
            else:
                fix_str = "**NO_PATCH_AVAILABLE**"

        report.append(f"| `{pkg['name']}` | `{pkg['version']}` | {pkg['ecosystem']} | {pkg['type']} | {vuln_str} | {fix_str} |")

    report.append("\n## Detailed Vulnerability Findings & Guidance\n")

    if not vulnerable_packages:
        report.append("No known vulnerabilities detected across scanned packages.")
    else:
        for pkg in vulnerable_packages:
            report.append(f"### Package: `{pkg['name']}` (v`{pkg['version']}`)\n")
            report.append(f"- **Location:** `{pkg['manifest']}`")
            report.append(f"- **Ecosystem:** {pkg['ecosystem']}")
            report.append(f"- **Dependency Type:** {pkg['type']}")
            if pkg.get('parent'):
                report.append(f"- **Dependency Chain:** `{pkg['parent']}` -> `{pkg['name']}`")
            
            for v in pkg['vulnerabilities']:
                report.append(f"\n#### Vulnerability ID: {v['id']}")
                report.append(f"- **Summary:** {v['summary']}")
                if v['references']:
                    report.append(f"- **Advisory Link:** {v['references'][0]}")
                
                if v['fixed_versions']:
                    report.append(f"- **Recommended Action:** Upgrade package to version `{v['fixed_versions'][0]}` or higher.")
                else:
                    report.append(f"- **Recommended Action:** `NO_PATCH_AVAILABLE`")
                    report.append(f"- **ATTENTION / NOTE:** No upstream fix or patched release is currently available in the official `{pkg['ecosystem']}` repository for this vulnerability. It is recommended to evaluate alternative packages, wrap usage in protective sanitization logic, or apply strict security controls to mitigate potential exploitation.")
            report.append("\n---")

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("\n".join(report))
    
    print(f"\n[+] Scan complete. Report successfully generated at: {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Agentic SCA & Dependency Scanner")
    parser.add_argument("--path", required=True, help="Path to project directory to scan")
    parser.add_argument("--output", default="sca_report.md", help="Output markdown report file path")

    args = parser.parse_args()

    scanner = DependencyScanner(args.path)
    dependencies = scanner.scan_directory()

    print(f"[*] Identified {len(dependencies)} total dependencies across project manifests.")
    print("[*] Auditing packages against OSV Advisory API...")

    audited_results = []
    for pkg in dependencies:
        audited_results.append(OSVAuditor.check_vulnerability(pkg))

    generate_report(audited_results, args.output)

if __name__ == "__main__":
    main()
