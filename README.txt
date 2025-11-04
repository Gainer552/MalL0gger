                        MalL0gger

Overview

MalL0gger is a pure Bash static malware analysis tool designed to safely 
collect forensic data and intelligence from any file type without executing it.

It performs a full-spectrum static analysis using only built-in Linux utilities 
and produces a timestamped, immutable report in plain text format.

MalL0gger is ideal for field operations, digital forensics, malware research, 
and triage in restricted or air-gapped environments where installing heavy 
frameworks is impractical.

Key Features

• Universal File Support
  - Analyzes any file type: executables, scripts, documents, archives, images, 
    firmware blobs, and unknown binary data.

• Full Static Analysis Pipeline
  - Metadata extraction (permissions, timestamps, MIME type).
  - Cryptographic fingerprints (MD5, SHA1, SHA256, SHA512).
  - Shannon entropy calculation.
  - Header parsing (ELF, PE, ZIP, UPX detection).
  - String and IOC extraction (URLs, IPs, domains, registry keys).
  - Certificate and crypto artifact detection.
  - Binary structure recognition (ELF/PE).
  - Optional YARA integration (if available).

• Smart Categorization
  - Separates collected information into logical sections:
    metadata, hashes, entropy, strings, indicators, and certificates.

• Forensic Integrity
  - Every report is timestamped and locked immutable (via chattr +i or chmod 400)
    to preserve the chain of custody.

• Zero Dependencies
  - Requires only standard Linux utilities:
    bash, file, stat, strings, awk, hexdump, sha256sum, md5sum, etc.

• Portable and Offline
  - Runs in any shell environment, including minimal recovery systems, 
    air-gapped analysis labs, or live-response USB drives.

Usage

Syntax: sudo ./mall0gger.sh

Example: sudo ./mall0gger.sh

Output:
    A detailed static analysis report will be written to the same directory:
        analysis_<filename>_<timestamp>.txt

    The report includes:
    - File metadata and hashes.
    - Entropy statistics.
    - Header dump and string extraction.
    - Network indicators and embedded resources.
    - Certificate and key artifacts.
    - Analyst notes and next-step suggestions.

Typical Workflow

1. Copy the suspect file to a safe, isolated location.
2. Execute MalL0gger against the target.
3. Review the generated report for:
   - Suspicious domains, IPs, and URLs.
   - Embedded certificates or key fragments.
   - API names or registry access strings.
   - Entropy anomalies suggesting packing or encryption.
4. Submit hashes to trusted intel sources (MISP, VirusTotal, etc.).
5. Archive the immutable report for reference.

Design Philosophy

MalL0gger was built to demonstrate that complete static analysis is possible 
with nothing but native shell tools. Its design goals are:

- Maximum transparency and reproducibility.
- Operational resilience in restricted environments.
- Safety: strictly static, read-only operations (never executes a sample).
- Forensic discipline: tamper-proof output with timestamp integrity.

Sample Use Cases

• Field incident response on compromised Linux systems.
• Quick triage of suspicious files in isolated environments.
• Demonstration or training of static analysis fundamentals.
• Forensic preservation of malware samples.
• Research on entropy or embedded IOCs in arbitrary data.

Output Example (simplified)

-------------------------------------------------
MalL0gger Static Analysis Report
Sample: /samples/malware_test_sample.bin
Generated: 2025-11-04 15:38:19Z
-------------------------------------------------
[Basic Metadata]
  MIME Type: application/octet-stream
  Owner: root:root
  Permissions: -rw-r--r--

[Hashes]
  MD5: ...
  SHA256: ...
  SHA512: ...

[Entropy]
  7.46 bits/byte (suggests packing or encryption)

[Indicators]
  http://example.test/infect/path
  192.0.2.123
  very.long.subdomain.chain.example-test-domain.net

[Certificate]
  -----BEGIN CERTIFICATE-----
  ...

[Notes]
  Static analysis complete — report locked immutable.
-------------------------------------------------

Legal Disclaimer

MalL0gger is provided for educational, research, and defensive security 
purposes only.

Do NOT use this tool to analyze, distribute, or interact with malicious 
code on production systems or networks that you do not own or have 
authorization to examine.

The author assumes no liability for misuse, data loss, or damage resulting 
from the use of this software. All analysis must be conducted in a controlled, 
isolated environment with proper legal authorization.

By using MalL0gger, you agree to comply with all applicable laws and 
regulations governing malware handling and cybersecurity research.
