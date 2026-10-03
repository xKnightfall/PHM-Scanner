# Changelog

All notable changes to PHM-Scanner will be documented here.

## 0.1.5 - 2026-10-03

First public preview under the PHM-Scanner name.

### Added

- Canonical target resolution shared by direct and recursive analysis.
- Bounded recursive investigation queue with node, depth, time, and duplicate limits.
- Safe ZIP member materialization into an investigation workspace.
- Recursive archive and extracted-image analysis through the normal resolver.
- Provenance tracking for recursive artifacts and pivot relationships.
- Regression coverage for canonical resolution, nested archives, workspace safety, recursive image analysis, and IPv4 indicator classification.

### Improved

- Direct and recursively discovered files now receive the same specialized analyzer selection.
- ZIP extraction now enforces member, total-size, and traversal safeguards.
- Investigation leads are ranked and re-submitted through one analysis pipeline.
- Terminal reports present recursive pivots and artifacts more compactly.

### Fixed

- Removed duplicate target-planning logic from the CLI and investigation runner.
- Fixed recursive resolver handling for `pathlib.Path` targets.


### Added

- PNG chunk inspection, text-chunk identification, and trailing-data detection during native image triage.
- ZIP entry listing and encrypted-archive indicators during native archive triage.
- Main `phm analyze <target>` workflow.
- OSINT track documentation covering identity, domains, subdomains, DNS, infrastructure, network location, websites, and historical public sources.
- Public geolocation lookup for coordinates and place clues through OpenStreetMap/Nominatim, including reverse-geocoded addresses and map candidates.
- `phm` console command.
- `--banner` command showing the Projekt Hail Mary banner.
- Target detection for files, domains, IP addresses, URLs, emails, usernames, hashes, GitHub repositories, and encoded text.
- Startup banner for normal terminal reports, with `--no-banner` for quiet output.
- `--verbose` option for showing plugin names and raw evidence details.
- Rule-based next-step recommendations in reports.
- Base32, Base58, Base85, ASCII85, JWT, PEM, compressed blob, and Caesar-style decoding attempts.
- Basic PE and ELF triage hints during file analysis.
- Web checks for robots.txt, sitemap.xml, security.txt, security headers, cookies, CSP, HTML comments, JavaScript endpoints, parameters, and authentication clues.
- GitHub repository details for releases, activity, health indicators, dependency/project files, and project hints.

### Improved

- Reports now focus on summaries, interesting findings, and next steps instead of raw plugin output.
- Normal terminal reports now hide internal scoring.
- Existing checks now perform deeper first-pass analysis to reduce manual investigation.
- File analysis now extracts URLs, domains, emails, IPs, hashes, JWTs, API keys, tokens, embedded file signatures, possible secrets, language hints, and suspicious strings.
- Crypto search now avoids low-quality branches more aggressively.
- Encoded-text detection now handles Base32-like input better.
- Recommendations are more contextual for files, web targets, crypto input, infrastructure, and OSINT pivots.

### Fixed

- Unusual `Server` header values, such as intentionally malicious-looking strings, are no longer treated as detected technologies.

### Changed

- Renamed the public project direction to PHM-Scanner.
- Renamed the Python package and command to `phm`.
- Updated version display to `Projekt Hail Mary 0.1.5`.
- Documentation now uses simpler, more practical language.
- Roadmap now focuses on improving existing checks instead of adding more areas.

### Removed

- Removed unnecessary developer-focused documentation for the current single-maintainer stage.
