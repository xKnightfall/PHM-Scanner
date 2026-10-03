# OSINT track

The OSINT track is a collection of public-information pivots, not a claim that related entities belong to the same person or organization. Each result is a lead with supporting evidence.

## Areas covered

### Identity

- Usernames and public profiles
- Email addresses and domain relationships
- GitHub users, organizations, repositories, releases, commits, and project files
- Public links and referenced usernames

### Domain and DNS

- Domain ownership and registration data through RDAP/WHOIS
- DNS records and nameservers
- Subdomains from public certificate-transparency records
- Reverse DNS and IP relationships
- DNSSEC and wildcard-DNS indicators when available
- Mail providers and hosting clues from DNS records

### Infrastructure and location

- IP address ownership and ASN
- Network, organization, country, region, and city fields when a public source provides them
- Hosting, CDN, nameserver, and reverse-DNS clues
- TLS certificates, certificate names, issuers, and expiry
- Related domains and infrastructure pivots

Location is reported as source-provided network metadata. It is not treated as a person's physical location.

### Websites and public content

- HTTP metadata and safe technology indicators
- Security headers and cookies
- `robots.txt`, `sitemap.xml`, and `security.txt`
- JavaScript files, routes, endpoints, parameters, forms, and authentication clues
- Public emails, domains, usernames, repository references, and downloadable files
- Historical snapshots where available

## Pivot behavior

Useful artifacts are classified and sent to the appropriate track:

```text
username → OSINT → repository → OSINT → domain → OSINT → image → Steg → encoded text → Cryptography
```

PHM does not infer identity from a matching username alone. Network geolocation is treated as infrastructure context, not proof of where a person is located. Public-source failures are recorded without stopping the rest of an investigation.
