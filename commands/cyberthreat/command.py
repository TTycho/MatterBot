"""
This module allows to query the cyberthreat.nl API for threat intelligence data.
"""
import logging
from datetime import datetime
from typing import List
from core.typevalidators import Domain, IPv4, String
from core.helpers  import api_get_with_auth_token

try:
    from . import settings
except ImportError:
    from . import defaults as settings

SERVICE_NAME = 'cyberthreat.nl *Hosting Intelligence* API'

"""
Any public functions in this module will be registered as commands by MatterBot. 
The first function will be the default command.
Each function must accept parameters: List[TypeValidator], options: str, *args, **kwargs.
The typevalidators used in the parameters list can be found int core/typevalidators.py
Input will be validated and normalized. There is no need to convert hostnames to bare domain names,
use the Domain type if you do not want to have subdomains included.

The parameters will be passed in a list, type hint List[TypeValidator]. Process the parameters accordingly.
Docstrings are used for help texts. There is no need for a help command.
"""


def query(parameters: List[Domain | IPv4], options: str, modules=None, *args, **kwargs) -> dict:
    """
    Query the cyberthreat API for a domain or IPv4 address.
    Input must be an _IP address_ or something with a _domain name_ such as a hostname, fully qualified domain name, URL etc.
    The returned actor handle can also be queried for further information with the **actor** command.
    """

    # return help if no parameters are given
    if parameters == []:
        return modules['help']['commands']['explain']['function'](parameters=['@ct'], options=None, modules=modules)
    

    filters = '&'.join(settings.APIURL['cyberthreat']['filters'])
    # always create the structured result early so we can return it unconditionally
    data = {
        "module": __package__,
        "source": SERVICE_NAME,
        "responses": [],
        "message": ""
    }



    """
    Data is received from the modules in the dict format:

    {
            "source": SERVICE_NAME,
            "module": __package__,
            "responses": [
            {
                "paragraph":"subtitle",
                "preamble":"introduction to source",
                "data": [
                    {"category":"Indicator", "datapoint":"IP address", "stix-type":"ipv4-addr", "value":"value"},
                    {"category":"Indicator", "datapoint":"datapoint", "value":"value"},
                    {"category":"Indicator", "datapoint":"Comment", "value":"Free text giving context on the indicator."}
                    
                ]
            }
        ],
        "message": "Textual message instead of data [optional]"
        "errormessage": "Optional error message"
    }

    No hit:
    {
        "source":"provider",
        "responses": []
    }   "module": __package__,
    
    Error:
    {
        "errormessage": "Error message. Data optional."
    }
    """

    # Example usage of type checking
    response = -1
    try:
        for param in parameters:
            if isinstance(param, Domain):
                logging.debug(f"Processing parameter: '{param}' as a domain")

                base_url = settings.APIURL['cyberthreat']['url']
                url = f"{base_url}domains?domain={param}&{filters}"
                results = api_get_with_auth_token(url,  settings.APIURL['cyberthreat']['apikey'])
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

                    # data['responses'].append({})
                    data['responses'].append( {
                        "paragraph": "Domain search",
                        "preamble": text,
                        "data": [
                            {
                            "category": "Hosting",
                            "subcategory": "domain",
                            "datapoint": "domain",
                            "stix-type": "domain-name",
                            "value": domain,
                            }, {
                            "category": "Hosting",
                            "subcategory": "domain",
                            "datapoint": "actor",
                            "stix-type": "threat-actor",
                            "value": fqdnlist[domain]['actor'],
                            }, {
                            "category": "Hosting",
                            "subcategory": "domain",
                            "datapoint": "last seen",
                            "stix-type": "last-observed",
                            "value": fqdnlist[domain]['last_seen'].strftime('%Y-%m-%d'),
                            }, {
                            "category": "Hosting",
                            "subcategory": "actor",
                            "datapoint": "actor id",
                            "stix-type": "threat-actor",
                            "value": fqdnlist[domain]['actor'],
                            }, {
                            "category": "Hosting",
                            "subcategory": "actor",
                            "datapoint": "Type",
                            "stix-type": "threat-actor",
                            "value": fqdnlist[domain]['type'],
                            }, {
                            "category": "Hosting",
                            "subcategory": "actor",
                            "datapoint": "credibility",
                            "stix-type": "x_cyberthreat_credibility",
                            "value": settings.confidence_tabel[fqdnlist[domain]['credibility']]['short_description'],
                            }
                        ]
                    })

                    for item in fqdnlist[domain]['subdomains']:
                        data['responses'][response]['data'].append({
                            "category": "Subdomains",
                            "subcategory": "",
                            "datapoint": "fqdn",
                            "stix-type": "",
                            "value": item,
                        })

            if isinstance(param, IPv4):
                logging.debug(f"Processing ip parameter: {param}")

                base_url = settings.APIURL['cyberthreat']['url']
                url = f"{base_url}addresses/{param}?{filters}"
                results = api_get_with_auth_token(url,  settings.APIURL['cyberthreat']['apikey'])
                # results = results.get('results')
                addr_list = dict()

                for result in results:
                    address = result['address']
                    addr_list[address] = {}
                    last_seen = datetime.strptime(result['last_seen'], '%Y-%m-%dT%H:%M:%S.%f%z')
                    addr_list[address]['actor'] = result.get('actor')
                    addr_list[address]['type'] = result.get('type')
                    addr_list[address]['credibility'] = min(addr_list[address].get('credibility', 6), result['credibility'])
                    addr_list[address]['last_seen'] = max(addr_list[address].get('last_seen', last_seen), last_seen)

                for address in addr_list:
                    response += 1
                    text = (
                        f"`{address}` "
                        f"{settings.confidence_tabel[addr_list[address]['credibility']]['level']} "
                        f"used by the {addr_list[address]['type']} network of actor "
                        f"**{addr_list[address]['actor'].capitalize()}**.\n"
                    )

                    data['responses'].append({})
                    data['responses'][response] = {
                        "paragraph": "Address search",
                        "preamble": text,
                        "data": [
                            {
                            "category": "Hosting",
                            "subcategory": "Network",
                            "datapoint": "IP address",
                            "stix-type": "ipv4-addr",
                            "value": address,
                            }, {
                            "category": "Hosting",
                            "subcategory": "Network",
                            "datapoint": "actor",
                            "stix-type": "threat-actor",
                            "value": addr_list[address]['actor'],
                            }, {
                            "category": "Hosting",
                            "subcategory": "Network",
                            "datapoint": "last seen",
                            "stix-type": "last-observed",
                            "value": addr_list[address]['last_seen'].strftime('%Y-%m-%d'),
                            }, {
                            "category": "Hosting",
                            "subcategory": "Network",
                            "datapoint": "credibility",
                            "stix-type": "x_cyberthreat_credibility",
                            "value": settings.confidence_tabel[addr_list[address]['credibility']]['short_description'],
                            }
                        ]
                    }
                    
    except Exception as e:
        logging.error(f"Error querying cyberthreat.nl API: {e}")
        data['message'] = "## Error!\n" + str(e)

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
        base_url = settings.APIURL['cyberthreat']['url']
        url = f"{base_url}actors"
        results = api_get_with_auth_token(url,  settings.APIURL['cyberthreat']['apikey'])
        for actor_item in results.get('results', []):
            if actor_item.get('name', '').lower() == str(name).lower():
                resp = {
                    'paragraph': f"Actor {actor_item.get('name', 'unknown').capitalize()}",
                    'preamble': actor_item.get('description'),
                    'data': [{
                    "category": "Actor",
                    "subcategory": "",
                    "datapoint": "Actor Type",
                    "stix-type": "",
                    "value": actor_item.get('type', '')
                    }
                    ]
                }
                data['responses'].append(resp)
    except Exception as e:
        logging.error(f"Error querying cyberthreat.nl API: {e}")
        data['message'] = "## Error!\n" + str(e)

    return data

