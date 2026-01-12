# WP-NEXUS

WP-NEXUS is a lightweight WordPress security reconnaissance tool.

## Features
- Detects WordPress presence
- Enumerates plugins (passive & probe-based)
- Maps detected plugins to known CVEs
- Generates JSON security reports

## Usage

```bash
python3 wp_nexus.py -t targets.txt -o report.json
