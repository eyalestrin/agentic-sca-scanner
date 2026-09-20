# Agentic Software Composition Analysis (SCA) Scanner

An open-source dependency vulnerability scanner and resolution engine inspired by the architecture of [agentic-sast-scanner](https://github.com/eyalestrin/agentic-sast-scanner).

Instead of static code analysis (SAST), this tool focuses on **Software Composition Analysis (SCA)**: recursively discovering dependencies, mapping direct and transitive chains, matching installed package versions against known open-source vulnerability advisories (OSV/CVE/GHSA), and generating actionable remediation reports.

---

## Capabilities

- **Recursive Scanning:** Automatically traverses project directories and sub-folders to discover manifest files.
- **Transitive Dependency Resolution:** Parses lock files (`package-lock.json`, `Pipfile.lock`, `go.mod`) to uncover deeply nested indirect dependencies.
- **Open Advisory Querying:** Queries the official [OSV.dev API](https://osv.dev/) for real-time security advisory correlation across ecosystems.
- **Unpatched Dependency Detection (`NO_PATCH_AVAILABLE`):** Clearly identifies packages that contain known security flaws but lack an upstream patch or replacement version in official registries, including mitigation guidance notes.
- **Multi-Ecosystem Support:**
  - Node.js (`package.json`, `package-lock.json`)
  - Python (`requirements.txt`, `Pipfile.lock`)
  - Go (`go.mod`)

---

## File Structure

```
.
├── SKILL.md         # Skill definition for LLM/Agentic tool execution
├── sca_scanner.py   # Python execution script
└── README.md        # Documentation and guide
```

---

## Quick Start

### Requirements
- Python 3.8+ (Uses standard library packages only; no external `pip` dependencies required).

### Usage

Run the scanner against any project root or source code directory:

```bash
python sca_scanner.py --path /path/to/your/project --output sca_report.md
```

### Command Options
- `--path`: Root directory of the target project to scan (includes sub-directories).
- `--output`: Path where the Markdown summary report will be saved (default: `sca_report.md`).

---

## Report Features

The generated Markdown report includes:
1. **Executive Summary Matrix:** Overview of total package counts, vulnerable dependencies, and unpatched findings.
2. **Tabular Summary:** Quick reference table with package versions, locations, vulnerability IDs, and safe target upgrade versions.
3. **Deep Finding Detail & Remediation Guidance:** Full breakdown for each finding with direct advisory links, parent-child dependency trees, and explicit mitigation instructions for packages where no fixed version exists (`NO_PATCH_AVAILABLE`).
