# Agentic SCA Scanner

Recursively discovering dependencies across project sub-folders, identifying all direct and transitive packages, checking them against open-source vulnerability databases (such as OSV), and generating actionable remediation reports.

---

## Key Features

- **Recursive Sub-folder Scanning:** Discovers project manifests (`package.json`, `requirements.txt`) and lock files (`package-lock.json`, `Pipfile.lock`) across nested folders.
- **Transitive Dependency Resolution:** Distinguishes between top-level direct dependencies and deep nested transitive child dependencies.
- **OSV Database Integration:** Queries the official Open Source Vulnerability (OSV) API for verified package version advisories.
- **Remediation & Patch Detection:** Automatically checks for minimum fixed versions in official repositories.
- **Unpatched Vulnerability Detection:** Explicitly flags packages with known vulnerabilities where no upstream fix exists (`NO_PATCH_AVAILABLE`).

---

## Supported Ecosystems & Files

| Ecosystem | Direct Manifest | Lock File (Transitive Resolution) |
| :--- | :--- | :--- |
| **Node.js** | `package.json` | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| **Python** | `requirements.txt`, `pyproject.toml` | `Pipfile.lock`, `poetry.lock` |
| **Go** | `go.mod` | `go.sum` |
| **Java** | `pom.xml`, `build.gradle` | `gradle.lockfile` |
| **Ruby** | `Gemfile` | `Gemfile.lock` |
| **C# / .NET** | `.csproj`, `packages.config` | `packages.lock.json` |

---

## Repository Architecture

```text
agentic-sca-scanner/
├── SKILL.md          # Skill definition and agent system instructions
├── sca_scanner.py    # Core SCA engine (recursive parser & OSV query runner)
├── README.md         # Project documentation and setup guide
└── .gitignore        # Git exclusion rules
```

---

## Prerequisites

Ensure Python 3.8+ and Git are installed on your system.

### Installing Prerequisites

#### Windows
- **Python:** Download and run the official installer from [python.org](https://www.python.org/downloads/). Ensure **"Add Python to PATH"** is checked during installation.
- **Git:** Download and install [Git for Windows](https://git-scm.com/download/win).

#### Linux (Ubuntu/Debian / WSL)
```bash
sudo apt update
sudo apt install -y python3 python3-pip git
```

#### macOS
Install via [Homebrew](https://brew.sh/):
```bash
brew install python git
```

---

## Setup & Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/eyalestrin/agentic-sca-scanner.git
   cd agentic-sca-scanner
   ```

2. **Verify Python Installation:**
   `sca_scanner.py` utilizes built-in Python standard libraries (`json`, `urllib`, `re`, `argparse`, `os`), requiring no third-party `pip` dependencies.

   Check your Python version:
   ```bash
   python3 --version
   ```

---

## How to Run the Skill in VS Code

You can use this skill directly within Visual Studio Code or through an AI Coding Assistant (such as GitHub Copilot, Roo Code, or Cline).

### Option 1: Direct Terminal Execution
1. Open your project folder in VS Code (`File` > `Open Folder...`).
2. Open the integrated terminal (`Ctrl + ~` or `Cmd + ~`).
3. Run the scanner against your target workspace or repository:
   ```bash
   python3 /path/to/agentic_sca_scanner/sca_scanner.py --path . --output sca_report.md
   ```

   For the standard local checkout used in this environment:
   ```bash
   python3 ~/agentic_sca_scanner/sca_scanner.py --path . --output sca_report.md
   ```

   The scanner writes Markdown. Use a `.md` output filename; it does not
   generate HTML merely because the filename ends in `.html`.

### Option 2: AI Agent / Copilot Skill Integration
1. Copy `SKILL.md` into your workspace skills catalog (e.g., `.vscode/skills/SKILL.md` or `.github/copilot-instructions.md`).
2. Prompt your AI assistant in VS Code:
   > *"Perform an SCA scan on this repository using the rules in SKILL.md. Scan all manifests and lockfiles, check for transitive vulnerabilities, and generate a report."*

---

## Generated Artifacts

Executing the scanner produces the following outputs:

1. **`sca_report.md` (Markdown Security Report):**
   A structured report containing:
   - **Executive Summary:** Total packages scanned, direct vs. transitive count, total vulnerability count, and unpatched package count.
   - **Detailed Findings:** A breakdown for each vulnerable package including Package Name, Declared Version, Ecosystem, Location, Transitive Dependency Chain, Vulnerability ID (CVE/GHSA), Severity Level, Summary, Recommended Upgrade Action, or an explicit `NO_PATCH_AVAILABLE` note.

2. **Console Output:**
   Real-time progress logging showing package counts, API querying progress, and final report save confirmation.

---

## Troubleshooting & Limitations

- **Network Connection:** The scanner queries `https://api.osv.dev/v1/query` in real-time. An active internet connection is required to fetch vulnerability advisories.
- **Lockfile Recommendation:** Scanning directories without lockfiles (e.g., only `package.json` without `package-lock.json`) will scan declared version ranges rather than exact resolved transitive dependency trees.
- **Path Resolution:** If running `sca_scanner.py` from outside the target folder, always provide the explicit directory using the `--path` argument.
