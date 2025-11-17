#!/usr/bin/env python3
import re
import requests
import logging
import tldextract
from pathlib import Path
from datetime import datetime
from .  import cyberthreat
"""
Simplified the settings import to avoid redundant checks.
"""
try:
    from . import settings
except ModuleNotFoundError:
    from . import defaults as settings
from typing import List, Literal, TypedDict

# Define the allowed types for parameters
ParameterType = Literal['ipv4', 'domain']

# Define the structure of the `command` dictionary
class Command(TypedDict):
    parameters: List[ParameterType]


class commands():
    """
    This module allows to query the cyberthreat.nl API for threat intelligence data.
    """
    def __init__(self):
        self.module_name = 'cyberthreat'

    def query(self, command: Command, channel: str, username: str, files: list, conn) -> None:
        """
        Process the query command with type-checked parameters.
        """
        # Example usage of type checking
        parameters = command.get('parameters', [])
        if not parameters:
            logging.warning("No parameters provided in the command.")
            return

        for param in parameters:
            if param == 'ipv4':
                logging.info(f"Processing IPv4 parameter: {param}")
            elif param == 'domain':
                logging.info(f"Processing domain parameter: {param}")
            else:
                logging.error(f"Unexpected parameter type: {param}")

    def actor(self, command, channel, username, files, conn):
        results = cyberthreat.wget('actors')

        actorlist = dict()
        for actor in results['results']:
            actorlist[actor['name']]=actor

        pass


#print(f"Locals: {locals()}")
results = cyberthreat.wget('actors')

actorlist = dict()
for actor in results['results']:
    actorlist[actor['name']]=actor

# messages[module_name], channame, username, files, self.mmDriver
# def process(command, channel, username, params, files, conn):
def process(command, channel, username, files, conn):
    # {'command': '@ct', 'parameters': ['ep6pheij.com'], 'options': [], 'subcommand': 'query', 'type': 'domain'}
    filters = '&'.join(settings.APIURL['cyberthreat']['filters'])

    params = command.get('parameters', [])
    if len(params)>0:
        logging.debug(f"cyberthreat command called with params: {params}")
        params = params[0].replace('[', '').replace(']', '').replace('hxxp','http').lower()
        intro = f"cyberthreat.nl *Hosting Intelligence* API search for `{params}`:"
        listitem = '`\n- `'
        try:

            if params in actorlist:
                text = f"**{actorlist[params]['name'].capitalize()}**\n{actorlist[params]['description']}"

            elif re.search(r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\:[0-65535]*)?$", params):
                results = cyberthreat.wget('addresses/'+params+'?'+filters)
                for address in results:
                    last_seen = datetime.strptime(address['last_seen'], '%Y-%m-%dT%H:%M:%S.%f%z')
                    text=f"IPv4 address `{params}` {settings.confidence_tabel[address['credibility']]['level']} used by the actor **{address['actor'].capitalize()}**.\n"
                    text+=f"Last seen: {last_seen.strftime('%Y-%m-%d')}"
            elif params:
                extract = tldextract.extract(params)
                extracted_domain = extract.registered_domain
                if extracted_domain:
                    results = cyberthreat.wget('domains?domain='+extracted_domain+'&'+filters)
                    results = results.get('results')
                    fqdnlist = dict()
                    
                    """
                    resufle the list so we can work with it as we want.
                    """
                    for result in results:
                        domain = result['domain']
                        fqdn   = result['fqdn']
                        if not domain in fqdnlist:
                            fqdnlist[domain]={'subdomains': set()}
                        if not fqdn==domain:
                            fqdnlist[domain]['subdomains'].add(fqdn)
                        last_seen = datetime.strptime(result['last_seen'], '%Y-%m-%dT%H:%M:%S.%f%z')
                        fqdnlist[domain]['credibility']=min(fqdnlist[domain].get('credibility',10), result['credibility'])
                        fqdnlist[domain]['last_seen']=max(fqdnlist[domain].get('last_seen', last_seen), last_seen)
                        fqdnlist[domain]['actor'] = result.get('actor')
                        fqdnlist[domain]['type']  = result.get('type')
                    
                    if len(fqdnlist):
                        text='The domainname '

                        """
                        There should have been only one domain returned, but for robustness we do a for loop.
                        """
                        for domain in fqdnlist:
                            text+=f"`{domain}` {settings.confidence_tabel[fqdnlist[domain]['credibility']]['level']} hosted on the {fqdnlist[domain]['type']} network of actor **{fqdnlist[domain]['actor'].capitalize()}**.\n"
                            text+=f"Last seen: {fqdnlist[domain]['last_seen'].strftime('%Y-%m-%d')}.\n"
                            if len(fqdnlist[domain]['subdomains']):
                                text+=f"We have found the following subdomains: \n- `{listitem.join(fqdnlist[domain]['subdomains'])}`."
                else:
                    """ In case the params doesnt even look like a valid domain name. """
                    return

            if 'text' in locals():
                return {'messages': [
                    {'text': intro + '\n' + text},
                ]}
            #else:
            #    return {'messages': [
            #        {'text': 'cyberthreat API searched for `%s` without result' % (params.strip(),)}
            #    ]}
        except Exception as e:
            return {'messages': [
                {'text': 'An error occurred searching cyberthreat for `%s`:\nError: `%s`' % (params, e)},
            ]}
