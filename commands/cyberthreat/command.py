#!/usr/bin/env python3
"""
This module allows to query the cyberthreat.nl API for threat intelligence data.
"""
import logging
from datetime import datetime
from typing import List, Literal, TypedDict

from core.typevalidators import Domain, IPv4, String
from core import helpers  # use helpers.api_get_auth_token

try:
    from . import settings
except ModuleNotFoundError:
    from . import defaults as settings

SERVICE_NAME = 'cyberthreat.nl *Hosting Intelligence* API'


def query(parameters: List[Domain | IPv4], options: str, *args, **kwargs) -> dict:
    """
    Query the cyberthreat API with a domain or IPv4 address.
    """


    filters = '&'.join(settings.APIURL['cyberthreat']['filters'])
    # always create the structured result early so we can return it unconditionally
    data = {
        "module": __package__,
        "source": SERVICE_NAME,
        "responses": []
    }

    # Example usage of type checking
    response = -1
    try:
        for param in parameters:
            if isinstance(param, Domain):
                logging.debug(f"Processing domain parameter: {param}")

                base_url = settings.APIURL['cyberthreat']['url']
                url = f"{base_url}domains?domain={param}&{filters}"
                results = helpers.api_get_auth_token(url,  settings.APIURL['cyberthreat']['apikey'])
                results = results.get('results')
                fqdnlist = dict()

                for result in results:
                    domain = result['domain']
                    fqdn = result['fqdn']
                    if domain not in fqdnlist:
                        fqdnlist[domain] = {'subdomains': set()}
                    if fqdn != domain:
                        fqdnlist[domain]['subdomains'].add(fqdn)
                    last_seen = datetime.strptime(result['last_seen'], '%Y-%m-%dT%H:%M:%S.%f%z')
                    fqdnlist[domain]['credibility'] = min(fqdnlist[domain].get('credibility', 6), result['credibility'])
                    fqdnlist[domain]['last_seen'] = max(fqdnlist[domain].get('last_seen', last_seen), last_seen)
                    fqdnlist[domain]['actor'] = result.get('actor')
                    fqdnlist[domain]['type'] = result.get('type')

                if len(fqdnlist):
                    response += 1
                    text = (
                        f"`{domain}` "
                        f"{settings.confidence_tabel[fqdnlist[domain]['credibility']]['level']} "
                        f"hosted on the {fqdnlist[domain]['type']} network of actor "
                        f"**{fqdnlist[domain]['actor'].capitalize()}**.\n"
                    )

                    data['responses'].append({})
                    data['responses'][response]['paragraph'] = "Domain search"
                    data['responses'][response]['preamble'] = text
                    data['responses'][response]['data'] = list()
                    data['responses'][response]['data'].append({
                        "category": "Hosting",
                        "subcategory": "",
                        "datapoint": "domain",
                        "stix-type": "domain-name",
                        "value": domain,
                    })
                    data['responses'][response]['data'].append({
                        "category": "Hosting",
                        "subcategory": "",
                        "datapoint": "actor",
                        "stix-type": "threat-actor",
                        "value": fqdnlist[domain]['actor'],
                    })
                    data['responses'][response]['data'].append({
                        "category": "Hosting",
                        "subcategory": "",
                        "datapoint": "last seen",
                        "stix-type": "last-observed",
                        "value": fqdnlist[domain]['last_seen'].strftime('%Y-%m-%d'),
                    })
                    data['responses'][response]['data'].append({
                        "category": "Hosting",
                        "subcategory": "actor",
                        "datapoint": "actor id",
                        "stix-type": "threat-actor",
                        "value": fqdnlist[domain]['actor'],
                    })
                    data['responses'][response]['data'].append({
                        "category": "Hosting",
                        "subcategory": "actor",
                        "datapoint": "Type",
                        "stix-type": "threat-actor",
                        "value": fqdnlist[domain]['type'],
                    })
                    data['responses'][response]['data'].append({
                        "category": "Hosting",
                        "subcategory": "actor",
                        "datapoint": "credibility",
                        "stix-type": "x_cyberthreat_credibility",
                        "value": settings.confidence_tabel[fqdnlist[domain]['credibility']]['short_description'],
                    })
                    
                    for item in fqdnlist[domain]['subdomains']:
                        data['responses'][response]['data'].append({
                            "category": "Subdomains",
                            "subcategory": "",
                            "datapoint": "fqdn",
                            "stix-type": "",
                            "value": item,
                        })
    except Exception as e:
        data['responses'].append({
            'paragraph': 'Error',
            'preamble': str(e),
            'data': []
        })

    # Return either populated data or the empty dict created at the start.
    return data


def actor(parameters: List[String], options: str = None, *args, **kwargs):
    """
    Lookup an actor by name in the cyberthreat.nl API.
    """
    SERVICE_NAME = 'cyberthreat.nl *Hosting Intelligence* API'

    data = {"module": __package__, "source": SERVICE_NAME, "responses": []}
    params = parameters or []
    if not params:
        return data
    name = params[0] if isinstance(params, (list, tuple)) else params
    try:
        # use helpers.api_get_auth_token instead of cyberthreat.wget
        base_url = settings.APIURL['cyberthreat']['url']
        url = f"{base_url}actors"
        results = helpers.api_get_auth_token(url, cyberthreat.getapikey())
        for actor_item in results.get('results', []):
            if actor_item.get('name', '').lower() == str(name).lower():
                resp = {
                    'paragraph': f"Actor {actor_item.get('name', 'unknown').capitalize()}",
                    'preamble': actor_item.get('description'),
                    'data': [],
                }
                resp['data'].append({
                    "category": "Actor",
                    "subcategory": "",
                    "datapoint": "Actor Type",
                    "stix-type": "",
                    "value": actor_item.get('type', ''),
                })
                data['responses'].append(resp)
    except Exception as e:
        data['responses'].append({
            'paragraph': 'Error',
            'preamble': str(e),
            'data': []
        })
    return data

