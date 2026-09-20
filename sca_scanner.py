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

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

OSV_API_URL = "https://api.osv.dev/v1/query"
REPORT_MARKDOWN = "sca_report.md"
REPORT_HTML = "sca_report.html"
REPORT_JSON = "sca_report.json"
MANDATORY_PDF = "sca_security_report.pdf"

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


def report_summary(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    total_packages = len(results)
    vulnerable_packages = [r for r in results if r['vulnerabilities']]
    total_vulns = sum(len(r['vulnerabilities']) for r in vulnerable_packages)
    unpatched_count = 0

    for pkg in vulnerable_packages:
        for v in pkg['vulnerabilities']:
            if not v['fixed_versions']:
                unpatched_count += 1

    return {
        'total_packages': total_packages,
        'vulnerable_packages': vulnerable_packages,
        'total_vulns': total_vulns,
        'unpatched_count': unpatched_count,
    }


def generate_markdown_report(results: List[Dict[str, Any]], output_file: str):
    summary = report_summary(results)
    vulnerable_packages = summary['vulnerable_packages']
    report = []
    report.append("# Software Composition Analysis (SCA) & Vulnerability Report\n")
    report.append("## Executive Summary\n")
    report.append(f"- **Total Packages Identified:** {summary['total_packages']}")
    report.append(f"- **Vulnerable Packages:** {len(vulnerable_packages)}")
    report.append(f"- **Total Identified Vulnerabilities:** {summary['total_vulns']}")
    report.append(f"- **Packages with No Available Upstream Patch:** {summary['unpatched_count']}\n")

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


def html_escape(value: Any) -> str:
    return (str(value).replace('&', '&amp;').replace('<', '&lt;')
            .replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;'))


def generate_html_report(results: List[Dict[str, Any]], output_file: str):
    summary = report_summary(results)
    rows = []
    for package in results:
        vulnerabilities = package['vulnerabilities']
        vulnerability_text = '<br>'.join(html_escape(v['id']) for v in vulnerabilities) or 'None'
        fixes = [v['fixed_versions'][0] for v in vulnerabilities if v['fixed_versions']]
        fix_text = f"Upgrade to {html_escape(fixes[0])} or higher" if fixes else ('NO_PATCH_AVAILABLE' if vulnerabilities else 'N/A (Clean)')
        rows.append(
            f"<tr><td><b>{html_escape(package['name'])}</b></td>"
            f"<td>{html_escape(package['version'])}</td><td>{html_escape(package['ecosystem'])}</td>"
            f"<td>{html_escape(package['type'])}</td><td>{vulnerability_text}</td><td>{fix_text}</td></tr>"
        )

    details = []
    for package in summary['vulnerable_packages']:
        for vulnerability in package['vulnerabilities']:
            references = ''.join(
                f"<li><a href=\"{html_escape(url)}\">{html_escape(url)}</a></li>"
                for url in vulnerability['references']
            )
            fix = (f"Upgrade to {html_escape(vulnerability['fixed_versions'][0])} or higher"
                   if vulnerability['fixed_versions'] else 'NO_PATCH_AVAILABLE')
            details.append(
                f"<article class=\"finding\"><h3>{html_escape(vulnerability['id'])}: "
                f"{html_escape(package['name'])} {html_escape(package['version'])}</h3>"
                f"<p><b>Summary:</b> {html_escape(vulnerability['summary'])}</p>"
                f"<p><b>Manifest:</b> <code>{html_escape(package['manifest'])}</code> | "
                f"<b>Ecosystem:</b> {html_escape(package['ecosystem'])} | "
                f"<b>Type:</b> {html_escape(package['type'])}</p>"
                f"<p><b>Recommended Action:</b> {fix}</p>"
                f"<ul>{references}</ul></article>"
            )

    html = f"""<!doctype html>
<html><head><meta charset=\"utf-8\"><title>SCA Vulnerability Report</title>
<style>
* {{ box-sizing: border-box; }} body {{ margin: 20px; background: #f8fafc; color: #0f172a; font-family: Segoe UI, sans-serif; overflow-x: hidden; }}
main {{ max-width: 1200px; margin: auto; }} h1, h2 {{ color: #0f172a; }}
table {{ width: 100%; table-layout: fixed; border-collapse: collapse; background: white; margin: 16px 0 28px; }}
th, td {{ padding: 10px; text-align: left; vertical-align: top; border-bottom: 1px solid #e2e8f0; overflow-wrap: anywhere; word-break: break-word; }}
th {{ background: #e2e8f0; }} .finding {{ background: white; border-left: 4px solid #ea580c; padding: 14px; margin: 14px 0; overflow-wrap: anywhere; }}
code {{ overflow-wrap: anywhere; word-break: break-word; }} a {{ overflow-wrap: anywhere; }}
@media (max-width: 800px) {{ body {{ margin: 10px; }} th, td {{ padding: 7px; font-size: 13px; }} }}
</style></head><body><main>
<h1>Software Composition Analysis (SCA) &amp; Vulnerability Report</h1>
<h2>Executive Summary</h2>
<ul><li>Total Packages Identified: <b>{summary['total_packages']}</b></li>
<li>Vulnerable Packages: <b>{len(summary['vulnerable_packages'])}</b></li>
<li>Total Identified Vulnerabilities: <b>{summary['total_vulns']}</b></li>
<li>Packages with No Available Upstream Patch: <b>{summary['unpatched_count']}</b></li></ul>
<table><thead><tr><th>Package</th><th>Version</th><th>Ecosystem</th><th>Type</th><th>Vulnerabilities</th><th>Safe Upgrade</th></tr></thead>
<tbody>{''.join(rows) if rows else '<tr><td colspan=\"6\">No packages identified.</td></tr>'}</tbody></table>
<h2>Detailed Vulnerability Findings &amp; Guidance</h2>
{''.join(details) if details else '<p>No known vulnerabilities detected across scanned packages.</p>'}
</main></body></html>"""
    Path(output_file).write_text(html, encoding='utf-8')


def generate_pdf_report(results: List[Dict[str, Any]], output_file: str = MANDATORY_PDF):
    summary = report_summary(results)
    styles = getSampleStyleSheet()
    body = ParagraphStyle('BodyWrap', parent=styles['BodyText'], fontSize=9, leading=11, wordWrap='CJK')
    code = ParagraphStyle('CodeWrap', parent=body, fontName='Courier', fontSize=8, leading=10, wordWrap='CJK')
    document = SimpleDocTemplate(output_file, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    story = [Paragraph('Software Composition Analysis (SCA) &amp; Vulnerability Report', styles['Title']), Paragraph('Executive Summary', styles['Heading2'])]
    story.extend([Paragraph(f"Total Packages Identified: <b>{summary['total_packages']}</b>", body), Paragraph(f"Vulnerable Packages: <b>{len(summary['vulnerable_packages'])}</b>", body), Paragraph(f"Total Identified Vulnerabilities: <b>{summary['total_vulns']}</b>", body), Paragraph(f"Packages with No Available Upstream Patch: <b>{summary['unpatched_count']}</b>", body), Spacer(1, 10)])
    table_data = [['Package', 'Version', 'Ecosystem', 'Type', 'Vulnerabilities', 'Safe Upgrade']]
    for package in results:
        vulns = ', '.join(v['id'] for v in package['vulnerabilities']) or 'None'
        fixes = [v['fixed_versions'][0] for v in package['vulnerabilities'] if v['fixed_versions']]
        table_data.append([Paragraph(str(package['name']), body), Paragraph(str(package['version']), body), Paragraph(str(package['ecosystem']), body), Paragraph(str(package['type']), body), Paragraph(vulns, body), Paragraph(fixes[0] if fixes else ('NO_PATCH_AVAILABLE' if package['vulnerabilities'] else 'N/A'), body)])
    table = Table(table_data, repeatRows=1, colWidths=[100, 55, 65, 55, 115, 90])
    table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e2e8f0')), ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#cbd5e1')), ('VALIGN', (0, 0), (-1, -1), 'TOP'), ('PADDING', (0, 0), (-1, -1), 5)]))
    story.extend([table, Spacer(1, 14), Paragraph('Detailed Vulnerability Findings &amp; Guidance', styles['Heading2'])])
    if not summary['vulnerable_packages']:
        story.append(Paragraph('No known vulnerabilities detected across scanned packages.', body))
    for package in summary['vulnerable_packages']:
        for vulnerability in package['vulnerabilities']:
            story.extend([Paragraph(f"{vulnerability['id']}: {package['name']} {package['version']}", styles['Heading3']), Paragraph(f"<b>Summary:</b> {html_escape(vulnerability['summary'])}", body), Paragraph(f"<b>Manifest:</b> {html_escape(package['manifest'])} | <b>Ecosystem:</b> {package['ecosystem']} | <b>Type:</b> {package['type']}", body), Paragraph(f"<b>Recommended Action:</b> {html_escape(vulnerability['fixed_versions'][0]) if vulnerability['fixed_versions'] else 'NO_PATCH_AVAILABLE'}", body), Spacer(1, 8)])
    document.build(story)


def generate_json_report(results: List[Dict[str, Any]], output_file: str = REPORT_JSON):
    Path(output_file).write_text(json.dumps({
        'summary': {
            key: value for key, value in report_summary(results).items()
            if key != 'vulnerable_packages'
        },
        'packages': results,
    }, indent=2), encoding='utf-8')


def generate_reports(results: List[Dict[str, Any]], output_file: str):
    output_path = Path(output_file)
    suffix = output_path.suffix.lower()
    if suffix == '.html':
        generate_html_report(results, output_file)
    elif suffix == '.json':
        generate_json_report(results, output_file)
    elif suffix == '.pdf':
        generate_pdf_report(results, output_file)
    else:
        generate_markdown_report(results, output_file)
    if output_path.resolve() != Path(MANDATORY_PDF).resolve():
        generate_pdf_report(results, MANDATORY_PDF)
    print(f"\n[+] Report successfully generated at: {output_file}")
    print(f"[+] Mandatory PDF report generated at: {MANDATORY_PDF}")


def main():
    parser = argparse.ArgumentParser(description="Agentic SCA & Dependency Scanner")
    parser.add_argument("--path", required=True, help="Path to project directory to scan")
    parser.add_argument("--output", default=REPORT_MARKDOWN, help="Output report path (.md, .html, .json, or .pdf)")

    args = parser.parse_args()

    scanner = DependencyScanner(args.path)
    dependencies = scanner.scan_directory()

    print(f"[*] Identified {len(dependencies)} total dependencies across project manifests.")
    print("[*] Auditing packages against OSV Advisory API...")

    audited_results = []
    for pkg in dependencies:
        audited_results.append(OSVAuditor.check_vulnerability(pkg))

    generate_reports(audited_results, args.output)

if __name__ == "__main__":
    main()
