#!/usr/bin/env python3
from pydoc import text
import re
import requests
import logging
import tldextract
from pathlib import Path
from datetime import datetime
from typing import List, Literal, TypedDict

from . import cyberthreat
from core.typevalidators import Domain, IPv4, IPv6, URL, Hostname, LongString, String
"""
Simplified the settings import to avoid redundant checks.
"""
try:
    from . import settings
except ModuleNotFoundError:
    from . import defaults as settings

class commands():
    """
    This module allows to query the cyberthreat.nl API for threat intelligence data.
    """
    def __init__(self):
        self.module_name = self.__class__.__module__.split('.')[-1]
        self.service_name = 'cyberthreat.nl *Hosting Intelligence* API'

    def query(self, parameters: List[Domain|IPv4], options: str, *args, **kwargs) -> dict:
        """
        Query the cyberthreat API.
        """

        filters = '&'.join(settings.APIURL['cyberthreat']['filters'])
        # always create the structured result early so we can return it unconditionally
        data = {
            "module": self.module_name, 
            "source": self.service_name, 
            "responses": []
            }


        """
        Output data in the format
    \
        {
            "module": "Module name",
            "source":"full API name",
            "responses": [
            {
                "paragraph":"subtitle",
                "preamble":"introduction to source",
                "data": [
                {"category":"Indicator", "subcategory":"", "datapoint":"IP address", "stix-type":"ipv4-addr", "value":"value"},
                {"category":"Indicator", "subcategory":"", "datapoint":"datapoint", "value":"value"},
                {"category":"Indicator", "subcategory":"", "datapoint":"Comment", "value":"Free text giving context on the indicator."}
                
                ]
            }
            ]
        }
        
        No hit:
        {   "module": "Module name"
            "source": "full service name",
            "responses": []
        }

        category, datapoint and value are taken from the source. Only stix-type
        is the same across modules for values of the same type.

        Eventually converts to a message text and possibly an attachment.
        The text can have multiple paragraph with a short introduction of the source.

        """
        # Example usage of type checking
        response = -1
        for param in parameters:
            if isinstance(param, Domain):
                logging.debug(f"Processing domain parameter: {param}")
                # extract = tldextract.extract(param)
                # extracted_domain = extract.registered_domain
                # if param:
                results = cyberthreat.wget('domains?domain='+param+'&'+filters)
                results = results.get('results')
                fqdnlist = dict()


                for result in results:
                    domain = result['domain']
                    fqdn   = result['fqdn']
                    if not domain in fqdnlist:
                        fqdnlist[domain]={'subdomains': set()}
                    if not fqdn==domain:
                        fqdnlist[domain]['subdomains'].add(fqdn)
                    last_seen = datetime.strptime(result['last_seen'], '%Y-%m-%dT%H:%M:%S.%f%z')
                    fqdnlist[domain]['credibility']=min(fqdnlist[domain].get('credibility',6), result['credibility'])
                    fqdnlist[domain]['last_seen']=max(fqdnlist[domain].get('last_seen', last_seen), last_seen)
                    fqdnlist[domain]['actor'] = result.get('actor')
                    fqdnlist[domain]['type']  = result.get('type')
                
                if len(fqdnlist):
                    response += 1
                    # initialize text before concatenation to avoid UnboundLocalError
                    text = f"`{domain}` {settings.confidence_tabel[fqdnlist[domain]['credibility']]['level']} hosted on the {fqdnlist[domain]['type']} network of actor **{fqdnlist[domain]['actor'].capitalize()}**.\n"

                    data['responses'].append({})
                    data['responses'][response]['paragraph'] = "Domain search"
                    data['responses'][response]['preamble']  = text
                    data['responses'][response]['data'] = list()
                    data['responses'][response]['data'].append({"category":"Hosting", "subcategory":"", "datapoint":"domain", "stix-type":"domain-name", "value":domain})
                    data['responses'][response]['data'].append({"category":"Hosting", "subcategory":"", "datapoint":"actor", "stix-type":"threat-actor", "value":fqdnlist[domain]['actor']})
                    data['responses'][response]['data'].append({"category":"Hosting", "subcategory":"", "datapoint":"credibility", "stix-type":"x_cyberthreat_credibility", "value":settings.confidence_tabel[fqdnlist[domain]['credibility']]['short_description']})
                    data['responses'][response]['data'].append({"category":"Hosting", "subcategory":"", "datapoint":"last seen", "stix-type":"last-observed", "value":fqdnlist[domain]['last_seen'].strftime('%Y-%m-%d')})
                    for item in fqdnlist[domain]['subdomains']:
                        data['responses'][response]['data'].append({"category":"Domain", "subcategory":"", "datapoint":"fqdn", "stix-type":"", "value":item})
        
        '''Return either data or the empty data dict created at the start.'''
        return data
        

    def actor(self, parameters: List[String], options: str = None, *args, **kwargs):
        """Lookup an actor by name and return structured result dict.

        Parameters expected: parameters[0] = actor name (string)
        Returns dict: { 'module': ..., 'source': ..., 'responses': [ { 'paragraph', 'preamble', 'data': [...] } ] }
        """
        data = {"module": self.module_name, "source": self.service_name, "responses": []}
        params = parameters or []
        if not params:
            return data
        name = params[0] if isinstance(params, (list, tuple)) else params
        try:
            results = cyberthreat.wget('actors')
            for actor in results.get('results', []):
                if actor.get('name', '').lower() == str(name).lower():
                    resp = {
                        'paragraph': f"Actor {actor.get('name','unknown').capitalize()}",
                        'preamble': actor.get('description'),
                        'data': []
                    }
                    resp['data'].append({"category": "Actor", "subcategory": "", "datapoint": "Actor Type", "stix-type": "", "value": actor.get('type', '')})
                    data['responses'].append(resp)
                    return data
        except Exception:
            return data
        # actor not found -> return empty responses
        return data
