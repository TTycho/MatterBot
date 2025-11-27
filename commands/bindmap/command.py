"""
This module exposes the mapping of loaded modules to their binds
"""
import logging
from typing import List
from core.typevalidators import Domain, IPv4, String
from core import helpers  # use helpers.api_get_auth_token

try:
    from . import settings
except ModuleNotFoundError:
    from . import defaults as settings

SERVICE_NAME = 'cyberthreat.nl *Hosting Intelligence* API'


def default(parameters: List[String], options: List[str], *, files=None, modules=None, **kwargs):
    """
    Default command for the bindmap module.

    Return a structured dict called `data` that maps loaded modules
    to their binds and descriptions, using the standard response format.
    """
    # Guard: modules dict is required; if not provided, we cannot do anything.
    if not modules:
        log.warning("bindmap.default called without modules context")
        return {
            "module": __package__,
            "source": SERVICE_NAME,
            "responses": [],
        }

    # Single response containing all module datapoints
    response = {
        "paragraph": "Loaded modules and their binds",
        "preamble": __doc__,
        "data": [],
    }

    for module_name in sorted(modules):
        mod_info = modules[module_name]

        # Determine binds
        binds = mod_info.get('settings', {}).get('BINDS')
        if not binds and 'BINDS' in mod_info:
            binds = mod_info.get('BINDS')
        binds = binds or []
        binds_str = ', '.join(sorted(binds))

        # Availability is left as UNKNOWN; core handles per-channel permissions

        # Now add flat datapoints for this module
        response["data"].append({
            "category": "Module",
            "subcategory": module_name,
            "datapoint": "binds",
            "stix-type": "",
            "value": binds_str,
        })
 
    data = {
        "module": __package__,
        "source": SERVICE_NAME,
        "responses": [response],
    }

    return data