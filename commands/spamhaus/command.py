"""Spamhaus Intelligence API + DQS module."""
from typing import Any, Dict, List, Optional

import logging
from datetime import datetime, timezone
from core.typevalidators import Domain, IPv4, IPv6
from core.helpers import api_get_with_bearer_token

SERVICE_NAME = "Spamhaus"
BASE_URL = "https://api.spamhaus.org/api/intel"
REALM = "intel"

try:  # pragma: no cover - settings import resolution
    from . import settings
except ImportError:  # fall back to defaults when no overrides
    from . import defaults as settings

_AUTH_DATA = {
    'username': settings.APIURL['spamhaus']['username'],
    'password': settings.APIURL['spamhaus']['password'],
    'realm': REALM,
}

_META_DEFS = {
    'dimension': {'path': '/domains/dimensions', 'field': 'dimension'},
    'context': {'path': '/domains/contexts', 'field': 'context'},
}
_META_CACHE: Dict[str, Dict[str, str]] = {'dimension': {}, 'context': {}}


def _parse_options(options: Optional[str]) -> Dict[str, str]:
    """We havent decided how to handle options but here is an attempt by GPT-5.1"""
    parsed: Dict[str, str] = {}
    if not options:
        return parsed
    for part in options.split():
        if '=' in part:
            k, v = part.split('=', 1)
            parsed[k.strip().lower()] = v.strip()
    return parsed


def _get_meta(kind: str) -> Dict[str, str]:
    cache = _META_CACHE.get(kind)
    if cache:
        return cache
    definition = _META_DEFS[kind]
    body = api_get_with_bearer_token(
        token_url="https://api.spamhaus.org/api/v1/login",
        auth_data=_AUTH_DATA,
        url=f"{BASE_URL}/v2{definition['path']}",
        cache_key=__package__,
    )
    meta: Dict[str, str] = {}
    if isinstance(body, list):
        field = definition['field']
        for entry in body:
            key = entry.get(field)
            desc = entry.get('description')
            if key and desc:
                meta[str(key)] = str(desc)
    _META_CACHE[kind] = meta
    return meta


for _kind in _META_DEFS:  # pragma: no cover - preload with logging fallback
    try:
        _get_meta(_kind)
    except Exception:
        logging.exception("Failed to preload Spamhaus %s metadata", _kind)
        _META_CACHE[_kind] = {}


def ip(parameters: List[IPv4 | IPv6], options: str, modules=None, *args, **kwargs) -> dict:
    """Query Spamhaus SIA for reputation and listings on one or more IP addresses.

    Supports IPv4 and IPv6.
    """
    data = {
        'module': __package__,
        'source': SERVICE_NAME,
        'responses': [],
        'message': '',
    }

    opts = _parse_options(options)
    dataset = opts.get('dataset', 'ALL')
    timeframe = opts.get('time', 'live')  # live or history
    limit = opts.get('limit')

    for param in parameters:
        path = f"/byobject/cidr/{dataset}/listed/{timeframe}/{param}"
        params: Dict[str, str] = {}
        if limit:
            params['limit'] = limit
        body = api_get_with_bearer_token(
            token_url="https://api.spamhaus.org/api/v1/login",
            auth_data=_AUTH_DATA,
            url=f"{BASE_URL}/v1{path}",
            params=params,
            cache_key=__package__,
        )
        if not isinstance(body, dict):
            data['responses'].append({'paragraph': 'IP search', 'preamble': f"Unexpected response format for {param}.", 'data': []})
            continue
        results = body.get('results', [])
        rows = []
        for entry in results:
            ip_value = entry.get('ipaddress') or str(param)
            rows.append({
                'category': 'Indicator',
                'subcategory': 'IP',
                'datapoint': 'ip',
                'stix-type': 'ipv4-addr' if isinstance(param, IPv4) else 'ipv6-addr',
                'value': ip_value,
            })
            if 'dataset' in entry:
                rows.append({
                    'category': 'Spamhaus',
                    'subcategory': 'dataset',
                    'datapoint': 'dataset',
                    'stix-type': 'x-spamhaus-dataset',
                    'value': entry.get('dataset'),
                })
            if 'detection' in entry:
                rows.append({
                    'category': 'Spamhaus',
                    'subcategory': 'detection',
                    'datapoint': 'detection',
                    'stix-type': 'x-spamhaus-detection',
                    'value': entry.get('detection'),
                })
            if 'listed' in entry:
                rows.append({
                    'category': 'Spamhaus',
                    'subcategory': 'timeline',
                    'datapoint': 'listed',
                    'stix-type': 'last-observed',
                    'value': entry.get('listed'),
                })
            if 'valid_until' in entry:
                rows.append({
                    'category': 'Spamhaus',
                    'subcategory': 'timeline',
                    'datapoint': 'valid-until',
                    'stix-type': 'expiration',
                    'value': entry.get('valid_until'),
                })
        preamble = f"IP {param} checked in {dataset}/{timeframe}. {len(rows)} rows." if rows else f"IP {param} not found in {dataset}."
        data['responses'].append({'paragraph': 'IP search', 'preamble': preamble, 'data': rows})

    return data


def domain(parameters: List[Domain], options: str, modules=None, *args, **kwargs) -> dict:
    """Retrieve overall reputation, score and tags for one or more domains."""
    data = {
        'module': __package__,
        'source': SERVICE_NAME,
        'responses': [],
        'message': '',
    }

    for param in parameters:
        body = api_get_with_bearer_token(
            token_url="https://api.spamhaus.org/api/v1/login",
            auth_data=_AUTH_DATA,
            url=f"{BASE_URL}/v2/byobject/domain/{param}",
            cache_key=__package__,
        )
        if not isinstance(body, dict):
            data['responses'].append({'paragraph': 'Domain', 'preamble': f"Unexpected response format for {param}.", 'data': []})
            continue
        rows = []
        rows.append({
            'category': 'Domain',
            'subcategory': 'identity',
            'datapoint': 'domain',
            'stix-type': 'domain-name',
            'value': str(param),
        })

        summary_rows = [
            {
                'category': 'Domain',
                'subcategory': 'reputation',
                'datapoint': 'score',
                'stix-type': 'x-spamhaus-score',
                'value': body.get('score'),
            },
            {
                'category': 'Domain',
                'subcategory': 'reputation',
                'datapoint': 'domain',
                'stix-type': 'domain-name',
                'value': str(param),
            },
            {
                'category': 'Domain',
                'subcategory': 'abuse',
                'datapoint': 'flag',
                'stix-type': 'x-boolean',
                'value': body.get('abused'),
            },
            {
                'category': 'Domain',
                'subcategory': 'abuse',
                'datapoint': 'domain',
                'stix-type': 'domain-name',
                'value': str(param),
            },
            {
                'category': 'Domain',
                'subcategory': 'timeline',
                'datapoint': 'domain',
                'stix-type': 'domain-name',
                'value': str(param),
            },

            {
                'category': 'Domain',
                'subcategory': 'timeline',
                'datapoint': 'last-seen',
                'stix-type': 'timestamp',
                'value': datetime.fromtimestamp(body.get('last-seen'), tz=timezone.utc).isoformat(),
            },
        ]
        if body.get('deactivated-ts', False):
            rows.append({
                'category': 'Domain',
                'subcategory': 'lifecycle',
                'datapoint': 'deactivation-time',
                'stix-type': 'x-timestamp',
                'value': datetime.fromtimestamp(body.get('deactivated-ts', ''), tz=timezone.utc).isoformat()
            })


        rows.extend(summary_rows)

        tags = set(body.get('tags')) or set()
        for tag in tags:
            rows.append({
                'category': 'Domain',
                'subcategory': 'tags',
                'datapoint': 'tag',
                'stix-type': 'x-spamhaus-tag',
                'value': tag,
            })
        preamble = f"Domain {param}: score {body.get('score', 'n/a')}, tags {len(tags)}."
        data['responses'].append({'paragraph': 'Domain overview', 'preamble': preamble, 'data': rows})
    return data


def listing(parameters: List[Domain], options: str, modules=None, *args, **kwargs) -> dict:
    """Check whether one or more domains are currently listed by Spamhaus."""
    data = {
        'module': __package__,
        'source': SERVICE_NAME,
        'responses': [],
        'message': '',
    }

    for param in parameters:
        body = api_get_with_bearer_token(
            token_url="https://api.spamhaus.org/api/v1/login",
            auth_data=_AUTH_DATA,
            url=f"{BASE_URL}/v2/byobject/domain/{param}/listing",
            cache_key=__package__,
        )
        if not isinstance(body, dict):
            data['responses'].append({'paragraph': 'Listing', 'preamble': f"Unexpected response format for {param}.", 'data': []})
            continue
        rows = []
        for key in ('is-listed', 'listed-until', 'ts'):
            if key in body:
                rows.append({
                    'category': 'Domain',
                    'subcategory': 'listing',
                    'datapoint': key,
                    'stix-type': 'x-spamhaus-' + key,
                    'value': body.get(key),
                })
        preamble = f"Domain {param} is listed." if body.get('is-listed') else f"Domain {param} not listed."
        data['responses'].append({'paragraph': 'Listing', 'preamble': preamble, 'data': rows})
    return data


def reputation(parameters: List[Domain], options: str, modules=None, *args, **kwargs) -> dict:
    """Show detailed reputation dimensions and recent contexts for domains."""
    data = {
        'module': __package__,
        'source': SERVICE_NAME,
        'responses': [],
        'message': '',
    }

    dim_meta = _get_meta('dimension')
    ctx_meta = _get_meta('context')

    for param in parameters:
        dims = api_get_with_bearer_token(
            token_url="https://api.spamhaus.org/api/v1/login",
            auth_data=_AUTH_DATA,
            url=f"{BASE_URL}/v2/byobject/domain/{param}/dimensions",
            cache_key=__package__,
        )
        if not isinstance(dims, dict):
            data['responses'].append({'paragraph': 'Reputation', 'preamble': f"Unexpected dimensions response for {param}.", 'data': []})
            continue
        ctxs = api_get_with_bearer_token(
            token_url="https://api.spamhaus.org/api/v1/login",
            auth_data=_AUTH_DATA,
            url=f"{BASE_URL}/v2/byobject/domain/{param}/contexts",
            cache_key=__package__,
        )
        if not isinstance(ctxs, list):
            data['responses'].append({'paragraph': 'Reputation', 'preamble': f"Unexpected contexts response for {param}.", 'data': []})
            continue
        rows = []
        for dim, score in dims.items():
            rows.append({
                'category': 'Domain',
                'subcategory': 'dimension',
                'datapoint': dim,
                'stix-type': 'x-spamhaus-dimension',
                'value': score,
            })

        # Build a preamble summarizing recent contexts and add context rows
        parts: list[str] = []
        if ctxs:
            ctx_items = []
            for entry in ctxs:
                ctx = entry.get('context')
                label = ctx_meta.get(str(ctx), str(ctx)) if ctx else None
                if not ctx:
                    continue
                if label:
                    ctx_items.append(f"{label} ({ctx})")
                else:
                    ctx_items.append(str(ctx))
                # add a row for the short context identifier (database)
                rows.append({
                    'category': 'Domain',
                    'subcategory': 'context',
                    'datapoint': 'database',
                    'stix-type': 'x-spamhaus-database',
                    'value': ctx,
                })
            if ctx_items:
                parts.append(". ".join(ctx_items))
        preamble = " | ".join(parts) if parts else "Reputation contexts retrieved."
        data['responses'].append({'paragraph': 'Reputation', 'preamble': preamble, 'data': rows})
    return data


def senders(parameters: List[Domain], options: str, modules=None, *args, **kwargs) -> dict:
    """List sender IPs associated with one or more domains, with scores when available."""
    data = {
        'module': __package__,
        'source': SERVICE_NAME,
        'responses': [],
        'message': '',
    }
    for param in parameters:
        body = api_get_with_bearer_token(
            token_url="https://api.spamhaus.org/api/v1/login",
            auth_data=_AUTH_DATA,
            url=f"{BASE_URL}/v2/byobject/domain/{param}/senders",
            cache_key=__package__,
        )
        rows = []
        if isinstance(body, list):
            for item in body:
                ip = item.get('ip')
                rows.append({
                    'category': 'Sender',
                    'subcategory': 'IP',
                    'datapoint': 'ip',
                    'stix-type': 'ipv4-addr',
                    'value': ip,
                })
                if 'score' in item:
                    rows.append({
                        'category': 'Sender',
                        'subcategory': 'IP',
                        'datapoint': 'score',
                        'stix-type': 'x-spamhaus-score',
                        'value': item.get('score'),
                    })
            preamble = f"Found {len(body)} sender IPs for {param}."
        else:
            preamble = f"Senders lookup failed for {param}."
        data['responses'].append({'paragraph': 'Senders', 'preamble': preamble, 'data': rows})
    return data


def ns(parameters: List[Domain], options: str, modules=None, *args, **kwargs) -> dict:
    """List nameservers for one or more domains, including Spamhaus scores."""
    data = {
        'module': __package__,
        'source': SERVICE_NAME,
        'responses': [],
        'message': '',
    }
    for param in parameters:
        body = api_get_with_bearer_token(
            token_url="https://api.spamhaus.org/api/v1/login",
            auth_data=_AUTH_DATA,
            url=f"{BASE_URL}/v2/byobject/domain/{param}/ns",
            cache_key=__package__,
        )
        rows = []
        if isinstance(body, list):
            for item in body:
                ns_value = item.get('ns')
                rows.append({
                    'category': 'DNS',
                    'subcategory': 'NS',
                    'datapoint': 'ns',
                    'stix-type': 'domain-name',
                    'value': ns_value,
                })
                if 'score' in item:
                    rows.append({
                        'category': 'DNS',
                        'subcategory': 'NS',
                        'datapoint': 'score',
                        'stix-type': 'x-spamhaus-score',
                        'value': item.get('score'),
                    })
            preamble = f"Found {len(body)} nameservers for {param}."
        else:
            preamble = f"Nameserver lookup failed for {param}."
        data['responses'].append({'paragraph': 'Nameservers', 'preamble': preamble, 'data': rows})
    return data


def arecords(parameters: List[Domain], options: str, modules=None, *args, **kwargs) -> dict:
    """Resolve A and AAAA records for domains and include Spamhaus scores per IP."""
    data = {
        'module': __package__,
        'source': SERVICE_NAME,
        'responses': [],
        'message': '',
    }
    for param in parameters:
        body = api_get_with_bearer_token(
            token_url="https://api.spamhaus.org/api/v1/login",
            auth_data=_AUTH_DATA,
            url=f"{BASE_URL}/v2/byobject/domain/{param}/a",
            cache_key=__package__,
        )
        rows = []
        if isinstance(body, list):
            for item in body:
                ip = item.get('ip')
                try:
                    rows.append({
                        'category': 'DNS',
                        'subcategory': 'A',
                        'datapoint': 'ip',
                        'stix-type': 'ipv4-addr',
                        'value': IPv4(ip),
                    })
                    if 'score' in item:
                        rows.append({
                            'category': 'DNS',
                            'subcategory': 'A',
                            'datapoint': 'score',
                            'stix-type': 'x-spamhaus-score',
                            'value': item.get('score'),
                        })
                except ValueError:
                    pass
                try:
                    rows.append({
                        'category': 'DNS',
                        'subcategory': 'AAAA',
                        'datapoint': 'ip',
                        'stix-type': 'ipv6-addr',
                        'value': IPv6(ip),
                    })
                    if 'score' in item:
                        rows.append({
                            'category': 'DNS',
                            'subcategory': 'AAAA',
                            'datapoint': 'score',
                            'stix-type': 'x-spamhaus-score',
                            'value': item.get('score'),
                        })
                except ValueError:
                    pass

        if body:
            preamble = f"Found {len(body)} A/AAAA entries for {param}."
        else:
            preamble = f"A/AAAA lookup failed for {param}."
        data['responses'].append({
            'paragraph': 'A/AAAA records',
            'preamble': preamble,
            'data': rows
            })
    return data


def hostnames(parameters: List[Domain], options: str, modules=None, *args, **kwargs) -> dict:
    """List related hostnames for domains and whether each is listed by Spamhaus."""
    data = {
        'module': __package__,
        'source': SERVICE_NAME,
        'responses': [],
        'message': '',
    }
    for param in parameters:
        body = api_get_with_bearer_token(
            token_url="https://api.spamhaus.org/api/v1/login",
            auth_data=_AUTH_DATA,
            url=f"{BASE_URL}/v2/byobject/domain/{param}/hostnames",
            cache_key=__package__,
        )
        rows = []
        if isinstance(body, list):
            for item in body:
                hn = item.get('hostname')
                rows.append({
                    'category': 'Hostname',
                    'subcategory': 'listing',
                    'datapoint': 'hostname',
                    'stix-type': 'domain-name',
                    'value': hn,
                })
                if 'is-listed' in item:
                    rows.append({
                        'category': 'Hostname',
                        'subcategory': 'listing',
                        'datapoint': 'is-listed',
                        'stix-type': 'x-spamhaus',
                        'value': item.get('is-listed'),
                    })
            preamble = f"Found {len(body)} hostnames for {param}."
        else:
            preamble = f"Hostname lookup failed for {param}."
        data['responses'].append({'paragraph': 'Hostnames', 'preamble': preamble, 'data': rows})
    return data


def malhashes(parameters: List[Domain], options: str, modules=None, *args, **kwargs) -> dict:
    """Retrieve malware file hashes associated with domains, including hash type."""
    data = {
        'module': __package__,
        'source': SERVICE_NAME,
        'responses': [],
        'message': '',
    }
    for param in parameters:
        body = api_get_with_bearer_token(
            token_url="https://api.spamhaus.org/api/v1/login",
            auth_data=_AUTH_DATA,
            url=f"{BASE_URL}/v2/byobject/domain/{param}/malware/hashes",
            cache_key=__package__,
        )
        rows = []
        for item in body or []:
            hash_value = item.get('hash')
            rows.append({
                'category': 'Malware',
                'subcategory': 'hash',
                'datapoint': item.get('type', 'hash'),
                'stix-type': 'file',
                'value': hash_value,
            })
        # Only append a response when there are actual hits
        if rows:
            preamble = f"Found {len(rows)} malware hashes for {param}."
            data['responses'].append({'paragraph': 'Malware hashes', 'preamble': preamble, 'data': rows})
    return data

def malurls(parameters: List[Domain], options: str, modules=None, *args, **kwargs) -> dict:
    """Retrieve malware URLs associated with domains."""
    data = {
        'module': __package__,
        'source': SERVICE_NAME,
        'responses': [],
        'message': '',
    }
    for param in parameters:
        body = api_get_with_bearer_token(
            token_url="https://api.spamhaus.org/api/v1/login",
            auth_data=_AUTH_DATA,
            url=f"{BASE_URL}/v2/byobject/domain/{param}/malware/urls",
            cache_key=__package__,
        )
        rows = []
        for item in body or []:
            url_val = item.get('url')
            rows.append({
                'category': 'Malware',
                'subcategory': 'url',
                'datapoint': 'url',
                'stix-type': 'url',
                'value': url_val,
            })
        # Only append a response when there are actual hits
        if rows:
            preamble = f"Found {len(rows)} malware URLs for {param}."
            data['responses'].append({'paragraph': 'Malware URLs', 'preamble': preamble, 'data': rows})
    return data


def limits(parameters: List, options: str, modules=None, *args, **kwargs) -> dict:
    """Show Spamhaus account information, quota limits, and current usage."""
    data = {
        'module': __package__,
        'source': SERVICE_NAME,
        'responses': [],
        'message': '',
    }
    body = api_get_with_bearer_token(
        token_url="https://api.spamhaus.org/api/v1/login",
        auth_data=_AUTH_DATA,
        url=f"{BASE_URL}/v1/limits",
        cache_key=__package__,
    )
    if not isinstance(body, dict):
        data['responses'].append({'paragraph': 'Limits', 'preamble': 'Unexpected response format for limits.', 'data': []})
        return data
    rows = []
    account = body.get('account', {})
    limits_obj = body.get('limits', {})
    current = body.get('current', {})
    for k, v in account.items():
        rows.append({
            'category': 'Account',
            'subcategory': 'info',
            'datapoint': k,
            'stix-type': 'x-spamhaus-account',
            'value': v,
        })
    for k, v in limits_obj.items():
        rows.append({
            'category': 'Limits',
            'subcategory': 'max',
            'datapoint': k,
            'stix-type': 'x-spamhaus-limit',
            'value': v,
        })
    for k, v in current.items():
        rows.append({
            'category': 'Limits',
            'subcategory': 'usage',
            'datapoint': k,
            'stix-type': 'x-spamhaus-usage',
            'value': v,
        })
    preamble = "Limits retrieved; see rows for quota and current usage."
    data['responses'].append({'paragraph': 'Limits', 'preamble': preamble, 'data': rows})
    return data
