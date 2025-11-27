# ZeroTrustNPM

**ZeroTrustNPM** is an open-source Python-based security scanner for NPM implementing a Zero Trust philosophy. Detects supply chain attacks, typo-squatting, and integrity anomalies beyond standard CVEs. Verify every package, trust no module.

## Features

- **Vulnerability Scanning**: Checks against OSV.dev database for known vulnerabilities.
- **Typosquatting Detection**: Identifies packages with names similar to popular libraries.
- **Integrity Verification**: Compares local package integrity with remote registry data.
- **Metadata Forensics**: Analyzes package publication time and version history for suspicious activity.
- **Script Auditing**: Flags suspicious lifecycle scripts (preinstall, install, postinstall).

## Installation

You can install ZeroTrustNPM directly from source:

```bash
git clone https://github.com/Achuth07/ZeroTrustNPM.git
cd ZeroTrustNPM
pip install .
```

## Usage

Run the scanner on your project directory:

```bash
zero-trust-npm /path/to/your/npm/project
```

Or run it as a module:

```bash
python -m zerotrustnpm /path/to/your/npm/project
```

## License

MIT License
