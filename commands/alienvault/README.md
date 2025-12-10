# AlienVault OTX module

Query AlienVault OTX for indicators like IPs, hostnames, hashes and URLs.

## API documentation

- <https://otx.alienvault.com/api>

## Module documentation

This module wraps the AlienVault OTX indicator API in a MatterBot command.
Subcommands are organised by endpoint type (geo, reputation, malware,
url_list, passive_dns, analysis).

Public subcommands:

- `geo`: geo information for an IP address or hostname.
- `reputation`: reputation for an IP address (IPv4 or IPv6).
- `malware`: malware-related information for IPs or hostnames/domains.
- `urls`: associated URLs for IPs, hostnames/domains, or a URL itself.
- `passive`: passive DNS information for IPs or hostnames.
- `analysis`: file/hash analysis for MD5, SHA1, or SHA256 hashes.
