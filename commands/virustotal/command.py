"""Query VirusTotal v3 for threat intelligence via resource-based subcommands.

"""
import base64
from typing import List
from core.typevalidators import IPv4, IPv6, MD5, SHA1, SHA256, URL, Domain, Hostname
from core.helpers import api_get_with_auth_token

try:  # pragma: no cover - settings import resolution
    from . import settings
except ImportError:  # fall back to defaults when no overrides
    from . import defaults as settings


SERVICE_NAME = "VirusTotal"

BASE_URL: str = settings.APIURL['virustotal']['url']
API_KEYS = settings.APIURL['virustotal']['key']

def _pick_api_key() -> str:
    """Return an API key; keeps list/str compatibility with old settings."""

    try:
        # Old module used random.choice over a list; keep semantics similar
        from random import choice

        if isinstance(API_KEYS, (list, tuple)) and API_KEYS:
            return choice(API_KEYS)
        return str(API_KEYS)
    except Exception:  # pragma: no cover - extreme edge-case fallback
        return str(API_KEYS)


def _base_rows(attributes: dict) -> list[dict]:
    """Build base analysis rows shared across resource types.

    This keeps the legacy VirusTotal-specific shaping but now returns
    per-attribute row dicts instead of formatted strings.
    """

    rows: list[dict] = []

    for key in ('threat_names', 'tags'):
        values = attributes.get(key, [])
        for v in values:
            datapoint = 'threat-name' if key == 'threat_names' else 'tag'
            rows.append(
                {
                    'category': 'VirusTotal',
                    'subcategory': 'Classification',
                    'datapoint': datapoint,
                    'stix-type': 'x-virustotal',
                    'value': str(v),
                }
            )

    return rows


def _file_rows(attributes: dict) -> list[dict]:
    rows: list[dict] = []

    names: list[str] = []
    if 'bytehero_info' in attributes:
        names.append(str(attributes['bytehero_info']))
    popular = attributes.get('popular_threat_classification', {})
    if 'suggested_threat_label' in popular:
        names.append(str(popular['suggested_threat_label']))
    for entry in popular.get('popular_threat_name', []):
        value = entry.get('value')
        if value:
            names.append(str(value))
    for name in sorted(set(names)):
        rows.append(
            {
                'category': 'VirusTotal',
                'subcategory': 'File classification',
                'datapoint': 'name',
                'stix-type': 'x-virustotal',
                'value': name,
            }
        )

    if 'magic' in attributes:
        rows.append(
            {
                'category': 'VirusTotal',
                'subcategory': 'Metadata',
                'datapoint': 'magic',
                'stix-type': 'file',
                'value': str(attributes['magic']),
            }
        )
    if 'trid' in attributes:
        trid = attributes['trid']
        if isinstance(trid, list) and trid:
            ft = trid[0].get('file_type')
            prob = trid[0].get('probability')
            if ft:
                label = f"{ft} ({prob}%)" if prob is not None else str(ft)
                rows.append(
                    {
                        'category': 'VirusTotal',
                        'subcategory': 'Metadata',
                        'datapoint': 'file_type',
                        'stix-type': 'file',
                        'value': label,
                    }
                )

    return rows


def _ip_domain_cert_rows(attributes: dict) -> list[dict]:
    rows: list[dict] = []

    if 'last_https_certificate' not in attributes:
        return rows

    cert = attributes['last_https_certificate']
    domains: set[str] = set()
    subject = cert.get('subject', {})
    cn = subject.get('CN')
    if cn:
        domains.add(str(cn))
    ext = cert.get('extensions', {})
    san = ext.get('subject_alternative_name', [])
    for d in san:
        domains.add(str(d))
    for d in sorted(domains):
        rows.append(
            {
                'category': 'VirusTotal',
                'subcategory': 'Certificate',
                'datapoint': 'domain-name',
                'stix-type': 'domain-name',
                'value': d,
            }
        )

    pub = cert.get('public_key', {})
    algorithm = pub.get('algorithm', 'N/A')
    algo_key = pub.get(algorithm.lower(), {}) if isinstance(algorithm, str) else {}
    key_size = algo_key.get('key_size', 'N/A')
    signature_algorithm = cert.get('signature_algorithm', 'N/A')
    issuers: set[str] = set()
    issuer = cert.get('issuer', {})
    for part in ('O', 'OU', 'CN', 'C'):
        if part in issuer:
            issuers.add(str(issuer[part]))
    issuer_str = ', '.join(sorted(issuers)) if issuers else 'N/A'
    rows.append(
        {
            'category': 'VirusTotal',
            'subcategory': 'Certificate',
            'datapoint': 'certificate',
            'stix-type': 'x-virustotal',
            'value': f"Key: {algorithm}-{key_size}, Sig: {signature_algorithm}, Issuer: {issuer_str}",
        }
    )

    return rows


def _domain_dns_rows(attributes: dict) -> list[dict]:
    rows: list[dict] = []

    if 'last_dns_records' not in attributes:
        return rows

    dns_records = attributes['last_dns_records']
    grouped_records: dict[str, set[str]] = {}

    for record in dns_records:
        record_type = record.get('type')
        value = record.get('value')
        if not record_type or not value:
            continue
        grouped_records.setdefault(record_type, set()).add(str(value))

    for record_type, values in grouped_records.items():
        for value in sorted(values):
            if record_type == 'A':
                rows.append(
                    {
                        'category': 'DNS',
                        'subcategory': 'A',
                        'datapoint': 'address',
                        'stix-type': 'ipv4-addr',
                        'value': value,
                    }
                )
            elif record_type == 'AAAA':
                rows.append(
                    {
                        'category': 'DNS',
                        'subcategory': 'AAAA',
                        'datapoint': 'address',
                        'stix-type': 'ipv6-addr',
                        'value': value,
                    }
                )
            elif record_type == 'CNAME':
                rows.append(
                    {
                        'category': 'DNS',
                        'subcategory': 'CNAME',
                        'datapoint': 'hostname',
                        'stix-type': 'domain-name',
                        'value': value,
                    }
                )
            elif record_type == 'NS':
                rows.append(
                    {
                        'category': 'DNS',
                        'subcategory': 'NS',
                        'datapoint': 'hostname',
                        'stix-type': 'domain-name',
                        'value': value,
                    }
                )
            elif record_type == 'MX':
                rows.append(
                    {
                        'category': 'DNS',
                        'subcategory': 'MX',
                        'datapoint': 'hostname',
                        'stix-type': 'domain-name',
                        'value': value,
                    }
                )
            # elif record_type == 'TXT':
            #     rows.append(
            #         {
            #             'category': 'DNS',
            #             'subcategory': 'TXT',
            #             'datapoint': 'text',
            #             'stix-type': 'x-virustotal-dns-txt',
            #             'value': value,
            #         }
            #     )
            else:
                rows.append(
                    {
                        'category': 'DNS',
                        'subcategory': f'{record_type}',
                        'datapoint': 'value',
                        'stix-type': f'x-virustotal-dns-{record_type.lower()}',
                        'value': value,
                    }
                )

    return rows


def search(parameters: List[IPv4 | Domain], options: str, *args, **kwargs) -> dict:
    """Get VirusTotal reports for IPv4 addresses and registered domains."""
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "x-apikey": _pick_api_key(),
    }
    data = {"module": __package__, "source": SERVICE_NAME, "responses": [], "message": ""}

    for indicator in parameters:
        value = str(indicator)


        if isinstance(indicator, IPv4):
            endpoint = f"ip_addresses/{value}"
        else:
            endpoint = f"domains/{value}"

        url = f"{BASE_URL}{endpoint}"
        json_response = api_get_with_auth_token(url, None, headers)
        attributes = json_response.get('data', {}).get('attributes', {})
        rows: list[dict] = []

        # NOTE: VirusTotal does not define these probability thresholds.
        # We derive `probability` from last_analysis_stats and map it to a
        # custom human-readable verdict to keep the data machine-readable.
        stats = attributes.get('last_analysis_stats', {})
        total = float(sum(stats.values()) or 0.0)
        malicious = stats.get('suspicious', 0) + stats.get('malicious', 0)
        probability = round((malicious / total) * 100.0, 2) if total > 0 else 0.0
        if probability > 80:
            verdict = 'certain'
        elif probability > 60:
            verdict = 'highly likely'
        elif probability > 20:
            verdict = 'potentially'
        elif probability > 0:
            verdict = 'possibly'
        else:
            verdict = 'NOT'
        if total > 0:
            rows.append(
                {
                    'category': 'VirusTotal',
                    'subcategory': 'Analysis',
                    'datapoint': 'maliciousness',
                    'stix-type': 'x-virustotal',
                    'value': probability,
                }
            )

        rows.extend(_base_rows(attributes))
        rows.extend(_ip_domain_cert_rows(attributes))

        if isinstance(indicator, Domain):
            rows.extend(_domain_dns_rows(attributes))

        vt_type_default = 'ip_address' if isinstance(indicator, IPv4) else 'domain'
        vt_type = json_response.get('data', {}).get('type', vt_type_default).replace('_', '-')
        vt_url = f"https://www.virustotal.com/gui/{vt_type}/{value}"
 
        indicator_type = 'ip' if isinstance(indicator, IPv4) else 'domain'
        data["responses"].append(
            {
                "paragraph": f"VirusTotal: {indicator_type} report",
                "preamble": f"VirusTotal says `{value}` is **{verdict}** malicious.Full report: [link]({vt_url})",
                "data": rows,
            }
        )
    return data


def url(parameters: List[URL], options: str, *args, **kwargs) -> dict:
    """Get VirusTotal reports for URLs (http/https)."""
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "x-apikey": _pick_api_key(),
    }
    data = {"module": __package__, "source": SERVICE_NAME, "responses": [], "message": ""}
    
    for indicator in parameters:
        url_value = str(indicator)
        vt_id_bytes = base64.urlsafe_b64encode(url_value.encode())
        vt_id = vt_id_bytes.strip(b'=').decode()
        endpoint = f"urls/{vt_id}"
        url = f"{BASE_URL}{endpoint}"
        json_response = api_get_with_auth_token(url, None, headers)
        attributes = json_response.get('data', {}).get('attributes', {})
        rows: list[dict] = []
        rows.extend(_base_rows(attributes))

        if 'last_final_url' in attributes:
            rows.extend([
                {
                    'category': 'VirusTotal',
                    'subcategory': 'HTTP',
                    'datapoint': 'final_url',
                    'stix-type': 'url',
                    'value': str(attributes['last_final_url']),
                },
                {
                    'category': 'DNS',
                    'subcategory': 'A',
                    'datapoint': 'hostname',
                    'stix-type': 'domain-name',
                    'value': Domain(indicator),
                },
            ])

        vt_type = json_response.get('data', {}).get('type', 'url').replace('_', '-')
        vt_url = f"https://www.virustotal.com/gui/{vt_type}/{vt_id}"

        data["responses"].append(
            {
                "paragraph": "VirusTotal: url report",
                "preamble": f"VirusTotal reports for `{url_value}`: [link]({vt_url})",
                "data": rows,
            }
        )
    return data


def file(parameters: List[MD5 | SHA1 | SHA256], options: str, *args, **kwargs) -> dict:
    """Get file/hash analysis information and MITRE TTPs for hashes."""
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "x-apikey": _pick_api_key(),
    }

    data = {"module": __package__, "source": SERVICE_NAME, "responses": [], "message": ""}
    for indicator in parameters:
        hash_value = str(indicator)
        endpoint = f"files/{hash_value}"
        url = f"{BASE_URL}{endpoint}"
        json_response = api_get_with_auth_token(url, None, headers)
        attributes = json_response.get('data', {}).get('attributes', {})
        rows: list[dict] = []

        # MITRE behaviour tree
        mitre_url = f"{BASE_URL}{endpoint}/behaviour_mitre_trees"
        mitre_json = api_get_with_auth_token(mitre_url, None, headers)
        mitre_tree_names = ('Malwares', 'Subtechniques', 'Techniques', 'Tools')
        ttplist: list[dict] = []
        tacticslist: list[dict] = []
        data_node = mitre_json.get('data', {})
        zenbox = data_node.get('Zenbox', {}) if isinstance(data_node, dict) else {}
        tactics = zenbox.get('tactics', [])
        for tactic in tactics:
            tacticid = tactic.get('id')
            tacticname = tactic.get('name')
            tacticlink = tactic.get('link')
            if tacticid and not any(tacticid == _['id'] for _ in tacticslist):
                tacticslist.append({'id': tacticid, 'name': tacticname, 'link': tacticlink})
            for tree_name in (n.lower() for n in mitre_tree_names):
                if tree_name in tactic:
                    for ttp in tactic.get(tree_name, []):
                        ttpid = ttp.get('id')
                        ttpname = ttp.get('name')
                        ttplink = ttp.get('link')
                        if ttpid and not any(ttpid == _['id'] for _ in ttplist):
                            ttplist.append({'id': ttpid, 'name': ttpname, 'link': ttplink})
        if ttplist:
            for t in sorted(ttplist, key=lambda _: _['id']):
                rows.append(
                    {
                        'category': 'VirusTotal',
                        'subcategory': 'MITRE',
                        'datapoint': 'ttp',
                        'stix-type': 'attack-pattern',
                        'value': t['id'],
                    }
                )
        if tacticslist:
            for t in sorted(tacticslist, key=lambda _: _['id']):
                rows.append(
                    {
                        'category': 'VirusTotal',
                        'subcategory': 'MITRE',
                        'datapoint': 'tactic',
                        'stix-type': 'attack-pattern',
                        'value': t['id'],
                    }
                )

        rows.extend(_base_rows(attributes))
        rows.extend(_file_rows(attributes))

        vt_type = json_response.get('data', {}).get('type', 'file').replace('_', '-')
        vt_url = f"https://www.virustotal.com/gui/{vt_type}/{hash_value}"
        rows.append(
            {
                'category': 'VirusTotal',
                'subcategory': 'Link',
                'datapoint': 'report',
                'stix-type': 'x-virustotal',
                'value': vt_url,
            }
        )

        data["responses"].append(
            {
                "paragraph": "VirusTotal: file report",
                "preamble": f"VirusTotal report for `{hash_value}`: [link]({vt_url}).",
                "data": rows,
            }
        )
    return data
