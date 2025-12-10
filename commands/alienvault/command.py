"""Query AlienVault OTX for threat intelligence via endpoint-based subcommands.
"""
from typing import List
from core.typevalidators import IPv4, IPv6, Hostname, MD5, SHA1, SHA256, URL
from core.helpers import api_get_with_auth_token

try:
    from . import settings
except ImportError:  # fall back to defaults when no overrides
    from . import defaults as settings


SERVICE_NAME = "AlienVault OTX"

# Static configuration derived from settings
BASE_URL: str = settings.APIURL['alienvault']['url']
API_KEY: str = settings.APIURL['alienvault']['key']


def _analysis_rows(json_response: dict) -> list[dict]:
    rows: list[dict] = []
    analysis = json_response.get('analysis')
    if not analysis:
        return rows

    plugins = analysis.get('plugins', {})
    exif = plugins.get('exiftool', {}).get('results', {})
    exiftoolfields = {
        'Original_Filename': 'Filename',
        'File_Description': 'Description',
        'MIME_Type': 'MIME-type',
    }
    for field, label in exiftoolfields.items():
        if field in exif:
            value = str(exif[field])
            if value:
                rows.append(
                    {
                        'category': 'File Analysis',
                        'subcategory': 'EXIF',
                        'datapoint': field,
                        'stix-type': 'file',
                        'value': f"{label}: {value}",
                    }
                )

    info_results = analysis.get('info', {}).get('results', {})
    infofields = {
        'file_type': 'File type',
        'filesize': 'Filesize',
        'md5': 'MD5 hash',
        'sha1': 'SHA1 hash',
        'sha256': 'SHA256 hash',
        'ssdeep': 'SSDEEP hash',
    }
    for field, label in infofields.items():
        if field in info_results:
            value = str(info_results[field])
            if value:
                rows.append(
                    {
                        'category': 'File Analysis',
                        'subcategory': 'Metadata',
                        'datapoint': field,
                        'stix-type': 'file',
                        'value': f"{label}: {value}",
                    }
                )

    cuckoo = plugins.get('cuckoo', {}).get('result', {})
    signatures = cuckoo.get('signatures', [])
    for signature in signatures:
        if signature.get('name') == 'antivirus_virustotal':
            for detection in signature.get('data', []):
                for v in detection.values():
                    if v:
                        rows.append(
                            {
                                'category': 'File Analysis',
                                'subcategory': 'malware',
                                'datapoint': 'detection',
                                'stix-type': 'name',
                                'value': str(v),
                            }
                        )
            for family in signature.get('families', []):
                for v in family.values():
                    if v:
                        rows.append(
                            {
                                'category': 'File Analysis',
                                'subcategory': 'malware',
                                'datapoint': 'family',
                                'stix-type': 'name',
                                'value': str(v),
                            }
                        )
    return rows



def passive(parameters: List[IPv4 | IPv6 | Hostname], options: str, *args, **kwargs) -> dict:
    """Get passive DNS information for IPs or hostnames."""

    data = {"module": __package__, "source": SERVICE_NAME, "responses": [], "message": ""}

    for indicator in parameters:
        if isinstance(indicator, (IPv4, IPv6)):
            endpoint = f"{type(indicator).__name__}/{indicator}/passive_dns"
        else:
            endpoint = f"hostname/{indicator}/passive_dns"
        url = f"{BASE_URL}{endpoint}?limit=100"
        json_response = api_get_with_auth_token(url, API_KEY)

        rows: list[dict] = []
        hostnames: set[str] = set()
        for entry in json_response.get('passive_dns', []):
            hostname = entry.get('hostname')
            if hostname:
                hostnames.add(str(hostname))
        for hostname in sorted(hostnames):
            rows.append(
                {
                    'category': 'Passive DNS',
                    'subcategory': 'A records',
                    'datapoint': 'hostname',
                    'stix-type': 'domain-name',
                    'value': hostname,
                }
            )

        data["responses"].append(
            {
                "paragraph": f"AlienVault OTX: {endpoint}",
                "preamble": f"AlienVault OTX passive DNS for `{indicator}`.",
                "data": rows,
            }
        )
    return data


def geo(parameters: List[IPv4 | IPv6 | Hostname], options: str, *args, **kwargs) -> dict:
    """Get geo information for an IP address or hostname from OTX."""

    data = {"module": __package__, "source": SERVICE_NAME, "responses": [], "message": ""}
    if not parameters:
        data["message"] = "Provide an IP address or hostname for geo lookup."
        return data

    for indicator in parameters:
        if isinstance(indicator, (IPv4, IPv6)):
            endpoint = f"{type(indicator).__name__}/{indicator}/geo"
        else:  # Hostname
            endpoint = f"hostname/{indicator}/geo"
        url = f"{BASE_URL}{endpoint}?limit=10"
        json_response = api_get_with_auth_token(url, API_KEY)

        rows: list[dict] = []

        # ASN (autonomous system number and optional name)
        asn = json_response.get('asn', '')
        if asn:
            parts = asn.split(maxsplit=1)
            rows.extend([
                {
                    'category': 'Network Analysis',
                    'subcategory': 'Autonomous System',
                    'datapoint': 'ASN',
                    'stix-type': 'autonomous-system',
                    'value': parts[0] if parts else '',
                },
                {
                    'category': 'Network Analysis',
                    'subcategory': 'Autonomous System',
                    'datapoint': 'name',
                    'stix-type': 'autonomous-system',
                    'value': parts[1] if len(parts) > 1 else '',
                },
            ])

        rows.extend([
            {
                'category': 'Geolocation',
                'subcategory': 'Location',
                'datapoint': 'city',
                'stix-type': 'location',
                'value': json_response.get('city', ''),
            },
            {
                'category': 'Geolocation',
                'subcategory': 'Location',
                'datapoint': 'country',
                'stix-type': 'location',
                'value': json_response.get('country_name', ''),
            },
        ])

        data["responses"].append(
            {
                "paragraph": f"AlienVault OTX: {endpoint}",
                "preamble": f"AlienVault OTX geo information for `{indicator}`.",
                "data": rows,
            }
        )
    return data




def malware(parameters: List[IPv4 | IPv6 | Hostname], options: str, *args, **kwargs) -> dict:
    """Get malware-related information for IPs or hostnames/domains."""

    data = {"module": __package__, "source": SERVICE_NAME, "responses": [], "message": ""}
    if not parameters:
        data["message"] = "Provide an IP address or hostname for malware lookup."
        return data

    for indicator in parameters:
        if isinstance(indicator, (IPv4, IPv6)):
            endpoints = [f"{type(indicator).__name__}/{indicator}/malware"]
        else:
            endpoints = [
                f"hostname/{indicator}/malware",
                f"domain/{indicator}/malware",
            ]
        for endpoint in endpoints:
            url = f"{BASE_URL}{endpoint}?limit=10"
            json_response = api_get_with_auth_token(url, API_KEY)
            rows: list[dict] = []
            for entry in json_response.get('data', []):
                detections = entry.get('detections')
                if detections:
                    for val in detections.values():
                        if val:
                            rows.append(
                                {
                                    'category': 'File Analysis',
                                    'subcategory': 'Hash detections',
                                    'datapoint': 'detection',
                                    'stix-type': 'file',
                                    'value': str(val),
                                }
                            )
            data["responses"].append(
                {
                    "paragraph": f"AlienVault OTX: {endpoint}",
                    "preamble": f"AlienVault OTX malware data for `{indicator}`.",
                    "data": rows,
                }
            )
    return data



def analysis(parameters: List[MD5 | SHA1 | SHA256], options: str, *args, **kwargs) -> dict:
    """Get file/hash analysis information for MD5, SHA1, or SHA256 hashes."""

    data = {"module": __package__, "source": SERVICE_NAME, "responses": [], "message": ""}
    if not parameters:
        data["message"] = "Provide a MD5, SHA1 or SHA256 hash for analysis."
        return data

    for indicator in parameters:
        endpoint = f"file/{indicator}/analysis"
        url = f"{BASE_URL}{endpoint}?limit=10"
        json_response = api_get_with_auth_token(url, API_KEY)
        rows = _analysis_rows(json_response)
        data["responses"].append(
            {
                "paragraph": f"AlienVault OTX: {endpoint}",
                "preamble": f"AlienVault OTX file analysis for `{indicator}`.",
                "data": rows,
            }
        )
    return data



def urls(parameters: List[IPv4 | IPv6 | Hostname], options: str, *args, **kwargs) -> dict:
    """Get associated URLs for IPs, hostnames/domains or URLs. From a URL only the hostname will be taken."""

    data = {"module": __package__, "source": SERVICE_NAME, "responses": [], "message": ""}

    for indicator in parameters:
        if isinstance(indicator, (IPv4, IPv6)):
            endpoint = f"{type(indicator).__name__}/{indicator}/url_list"
        else:  # Hostname
            endpoint = f"hostname/{indicator}/url_list"
        url = f"{BASE_URL}{endpoint}?limit=10"
        json_response = api_get_with_auth_token(url, API_KEY)
        rows: list[dict] = []
        for e in json_response.get('url_list', []):
            url_value = e.get('url', '')
            rows.append(
                {
                    'category': 'Network Analysis',
                    'subcategory': 'Associated URLs',
                    'datapoint': 'url',
                    'stix-type': 'url',
                    'value': str(url_value),
                }
            )
        data["responses"].append(
            {
                "paragraph": f"AlienVault OTX: {endpoint.rsplit('/', 1)[-1]}",
                "preamble": f"AlienVault OTX URLs for `{indicator}`.",
                "data": rows,
            }
        )

    return data

