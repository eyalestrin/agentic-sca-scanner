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