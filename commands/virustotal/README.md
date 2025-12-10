# VirusTotal module

MatterBot module for querying VirusTotal (v3) for file, IP, domain and URL intelligence.

## API documentation

- [VirusTotal API v3 overview](https://docs.virustotal.com/reference/overview)
- [Get an IP address report](https://docs.virustotal.com/reference/ip-info)
- [Get a domain report](https://docs.virustotal.com/reference/domain-info)
- [Get a URL report](https://docs.virustotal.com/reference/url-info)
- [Get a file report](https://docs.virustotal.com/reference/file-info)

## Module documentation

This module exposes separate subcommands for each VirusTotal resource type:

- `file`: Look up file hashes (MD5, SHA1, SHA256).
- `ip`: Look up IPv4 addresses.
- `domain`: Look up registered domain names (no subdomains / hostnames).
- `url`: Look up URLs (must start with `http` or `https`).

Each subcommand returns structured response data for MatterBot to render, including verdicts, TLS/DNS details where applicable, and links to the VirusTotal GUI.
