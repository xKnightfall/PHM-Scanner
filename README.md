# PHM-Scanner

PHM-Scanner is a command-line tool that analyzes cybersecurity targets and performs the first steps of an investigation automatically.

Give it a file, website, IP address, domain, binary, image, hash, GitHub repository, or encoded text. PHM checks what it is, pulls out useful details, summarizes what matters, and suggests what to investigate next.

```bash
phm analyze <target>
```

## Projekt Hail Mary

Yes, it's a Ryan Gosling reference.

No, this tool won't solve astrophysics problems.

**Disclaimer:** Projekt Hail Mary is an independent open-source cybersecurity project. It is not affiliated with, endorsed by, sponsored by, or otherwise associated with Andy Weir, Project Hail Mary, Amazon MGM Studios, Sony Pictures, Ryan Gosling, or any related publishers, authors, production companies, or rights holders. The name is used solely as a lighthearted internal codename and reference.

## Why use it?

PHM saves time during the first pass of an investigation.

Instead of switching between several tools just to understand a target, you can start with one command and get a clean report.

It is useful for:

- CTFs
- OSINT investigations
- penetration testing
- digital forensics
- malware triage
- security research

PHM does not replace specialist tools like Ghidra, Burp Suite, CyberChef, Wireshark, or Nmap. It helps you decide what is worth opening in those tools.

## Quick examples

```bash
phm analyze challenge.zip
phm analyze suspicious.exe
phm analyze image.jpg
phm analyze example.com
phm analyze https://example.com
phm analyze 8.8.8.8
phm analyze person@example.com
phm analyze 5d41402abc4b2a76b9719d911017c592
phm analyze SGVsbG8=
```

Example output style:

```text
PHM Report :: suspicious.exe
================================
Detected:
  file

Summary
-------
File: suspicious.exe
Type: DOS/PE executable
SHA256: ...
Strings: 42
Extracted indicators: url: 1, domain: 1

Interesting findings:
  - Executable/binary file detected
  - URL found in strings

Findings
--------
- Native file triage
  File type, hashes, entropy, and strings were collected.

What to investigate next
------------------------
1. Review extracted strings
2. Analyze discovered URLs or domains
3. Perform binary triage next
```

## Kali Linux integration

PHM-Scanner is primarily a terminal application. A Debian/Kali package installs the `phm` command and adds a PHM-Scanner launcher to the Kali Applications menu under security and information-gathering categories. Selecting it opens a terminal and runs `phm` as the logged-in user.

For development, `pipx install -e .` installs the CLI but does not modify system application menus or icons. Menu integration is provided by the Debian/Kali package.

## Install

From the project folder:

```bash
python -m pip install -e .
```

When packaged, the intended install flow is:

```bash
pip install phm-scanner
```

Then run:

```bash
phm --help
phm --banner
phm analyze --help
phm analyze example.com
```

For normal terminal output, PHM prints the Projekt Hail Mary banner before the report. Use `--no-banner` if you want a quieter terminal run:

```bash
phm analyze example.com --no-banner
```

The banner is not added to JSON, CSV, Markdown, HTML, or files written with `--output`.

## Main command

Use this first:

```bash
phm analyze <target>
```

PHM tries to detect what you gave it and chooses useful checks.

Examples:

```bash
phm analyze example.com
```

Checks domain and network information.

```bash
phm analyze https://portswigger.net
```

Checks DNS, RDAP, TLS, headers, and website clues.

```bash
phm analyze suspicious.exe
```

Checks file type, hashes, entropy, strings, and suspicious indicators.

```bash
phm analyze SGVsbG8=
```

Attempts decoding and shows the best result.

## Direct commands

Most users should start with `phm analyze`, but direct commands are available when you already know what you want.

```bash
phm file sample.bin
phm binary sample.exe
phm image photo.jpg
phm document report.pdf
phm archive sample.zip
phm metadata report.pdf
phm domain example.com
phm dns example.com
phm ip 8.8.8.8
phm web https://example.com
phm email person@example.com
phm username analyst
phm hash 5d41402abc4b2a76b9719d911017c592
phm crypto SGVsbG8=
```

## Reports

Default terminal reports show:

- detected target type
- summary
- interesting findings
- next steps

Use `--verbose` when you want raw details:

```bash
phm analyze example.com --verbose
```

Other formats:

```bash
phm analyze example.com --format json
phm analyze sample.pdf --format html --output report.html
```

Supported formats:

- terminal
- JSON
- CSV
- Markdown
- HTML

## Save investigations

```bash
phm analyze example.com --save
phm storage list
phm storage show 1
```

Saved investigations use SQLite.

## What works today

PHM-Scanner currently supports:

- target detection
- readable reports
- next-step suggestions
- file type checks
- file hashes
- entropy
- string extraction
- URL, domain, email, IP, hash, JWT, API key, and token extraction
- embedded file signature checks
- possible secret checks
- basic binary triage hints
- hash identification
- Base64, Base32, Base58, Base85, hex, URL, ROT13, Caesar-style, JWT, compressed blob, and XOR-style decoding
- DNS lookup
- WHOIS lookup
- RDAP lookup
- IP lookup
- reverse DNS lookup
- ASN lookup
- TLS certificate lookup
- Certificate Transparency lookup
- web checks for headers, cookies, security headers, robots.txt, sitemap.xml, security.txt, comments, endpoints, and parameters
- GitHub user, organization, repository, and search checks
- Wayback Machine lookup

## What PHM-Scanner is not

PHM-Scanner is not:

- an auto-solver
- a pile of wrappers around other tools
- a replacement for specialist security tools

PHM-Scanner is meant to be the first tool you run, not the only tool you ever need.

## Development focus

The priority is not to add lots of new checks.

The priority is to make the existing checks deeper and more useful:

- better file analysis
- better binary triage
- better web analysis
- better GitHub repository review
- better crypto decoding
- better infrastructure summaries
- better reports

Guiding question:

```text
Did this save the user time or reduce manual work?
```

If the answer is no, it can wait.
