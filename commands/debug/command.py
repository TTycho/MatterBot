"""
This module provides a debug command that shows how MatterBot validates and normalizes
different input types.
"""
from typing import List
from core.typevalidators import String, LongString, Domain, IPv4, IPv6, Hostname, URL, Email, ASN

try:
    from . import settings
except ImportError:
    from . import defaults as settings


SERVICE_NAME = "Debug Module"


def test(
    parameters: List[String | LongString | Domain | IPv4 | IPv6 | Hostname | URL | Email | ASN],
    options: str,
    modules=None,
    *args,
    **kwargs,
) -> dict:
    """
    Debug command that accepts many different input types and reports:

    - which MatterBot type the input was validated as
    - the matching STIX type (where applicable)
    - the normalized value

    For each parameter type we also include an example of how a
    real module might structure its response, similar to the
    cyberthreat module's Domain and IPv4 handling.
    """
    # Cyberthreat-style empty-parameters behavior: delegate to help module for @debug
    if parameters == [] and modules is not None and "help" in modules:
        return modules["help"]["commands"]["explain"]["function"](
            parameters=["@debug"], options=None, modules=modules
        )

    data = {
        "module": __package__,
        "source": SERVICE_NAME,
        "responses": [],
    }

    if not parameters:
        # Fallback if help module is unavailable
        data["responses"].append(
            {
                "paragraph": "debug",
                "preamble": (
                    "This command accepts many different input types and shows which "
                    "validator and STIX type are used for each value.\n\n"
                    "Supported types: String, LongString, Domain, IPv4, IPv6, "
                    "Hostname, URL, Email, ASN."
                ),
                "data": [],
            }
        )
        return data

    for _, param in enumerate(parameters):
        # Domain
        if isinstance(param, Domain):
            data["responses"].append(
                {
                    "paragraph": "Domain input",
                    "preamble": (
                        "Input was validated as a Domain. "
                        f"The normalized registered domain is `{param}`."
                    ),
                    "data": [
                        {
                            "category": "Indicator",
                            "subcategory": "Domain",
                            "datapoint": "domain",
                            "stix-type": "domain-name",
                            "value": str(param),
                        },
                        {
                            "category": "Debug",
                            "subcategory": "Validator",
                            "datapoint": "type",
                            "stix-type": "x-matterbot-type",
                            "value": "Domain",
                        },
                    ],
                }
            )
            continue

        # IPv4
        if isinstance(param, IPv4):
            data["responses"].append(
                {
                    "paragraph": "IPv4 input",
                    "preamble": (
                        "Input was validated as an IPv4 address. "
                        f"The normalized address is `{param}`."
                    ),
                    "data": [
                        {
                            "category": "Indicator",
                            "subcategory": "Network",
                            "datapoint": "IP address",
                            "stix-type": "ipv4-addr",
                            "value": str(param),
                        },
                        {
                            "category": "Debug",
                            "subcategory": "Validator",
                            "datapoint": "type",
                            "stix-type": "x-matterbot-type",
                            "value": "IPv4",
                        },
                    ],
                }
            )
            continue

        # IPv6
        if isinstance(param, IPv6):
            data["responses"].append(
                {
                    "paragraph": "IPv6 input",
                    "preamble": (
                        "Input was validated as an IPv6 address. "
                        f"The normalized address is `{param}`."
                    ),
                    "data": [
                        {
                            "category": "Indicator",
                            "subcategory": "Network",
                            "datapoint": "IP address",
                            "stix-type": "ipv6-addr",
                            "value": str(param),
                        },
                        {
                            "category": "Debug",
                            "subcategory": "Validator",
                            "datapoint": "type",
                            "stix-type": "x-matterbot-type",
                            "value": "IPv6",
                        },
                    ],
                }
            )
            continue

        # Hostname
        if isinstance(param, Hostname):
            data["responses"].append(
                {
                    "paragraph": "Hostname input",
                    "preamble": (
                        "Input was validated as a Hostname. "
                        f"The normalized FQDN is `{param}`."
                    ),
                    "data": [
                        {
                            "category": "Indicator",
                            "subcategory": "Hostname",
                            "datapoint": "fqdn",
                            "stix-type": "domain-name",
                            "value": str(param),
                        },
                        {
                            "category": "Debug",
                            "subcategory": "Validator",
                            "datapoint": "type",
                            "stix-type": "x-matterbot-type",
                            "value": "Hostname",
                        },
                    ],
                }
            )
            continue

        # URL
        if isinstance(param, URL):
            data["responses"].append(
                {
                    "paragraph": "URL input",
                    "preamble": (
                        "Input was validated as a URL. "
                        f"The normalized URL is `{param}`."
                    ),
                    "data": [
                        {
                            "category": "Indicator",
                            "subcategory": "URL",
                            "datapoint": "url",
                            "stix-type": "url",
                            "value": str(param),
                        },
                        {
                            "category": "Debug",
                            "subcategory": "Validator",
                            "datapoint": "type",
                            "stix-type": "x-matterbot-type",
                            "value": "URL",
                        },
                    ],
                }
            )
            continue

        # Email
        if isinstance(param, Email):
            data["responses"].append(
                {
                    "paragraph": "Email input",
                    "preamble": (
                        "Input was validated as an Email address. "
                        f"The normalized address is `{param}`."
                    ),
                    "data": [
                        {
                            "category": "Indicator",
                            "subcategory": "Email",
                            "datapoint": "email-address",
                            "stix-type": "email-addr",
                            "value": str(param),
                        },
                        {
                            "category": "Debug",
                            "subcategory": "Validator",
                            "datapoint": "type",
                            "stix-type": "x-matterbot-type",
                            "value": "Email",
                        },
                    ],
                }
            )
            continue

        # ASN
        if isinstance(param, ASN):
            data["responses"].append(
                {
                    "paragraph": "ASN input",
                    "preamble": (
                        "Input was validated as an ASN. "
                        f"The normalized value is `{param}` (always stored as AS<number>)."
                    ),
                    "data": [
                        {
                            "category": "Indicator",
                            "subcategory": "Network",
                            "datapoint": "ASN",
                            "stix-type": "autonomous-system",
                            "value": str(param),
                        },
                        {
                            "category": "Debug",
                            "subcategory": "Validator",
                            "datapoint": "type",
                            "stix-type": "x-matterbot-type",
                            "value": "ASN",
                        },
                    ],
                }
            )
            continue

        # LongString
        if isinstance(param, LongString):
            data["responses"].append(
                {
                    "paragraph": "LongString input",
                    "preamble": (
                        "Input was validated as a LongString. "
                        "This is typically used for free-form text."
                    ),
                    "data": [
                        {
                            "category": "Text",
                            "subcategory": "LongString",
                            "datapoint": "value",
                            "stix-type": "x-matterbot-string",
                            "value": str(param),
                        },
                        {
                            "category": "Debug",
                            "subcategory": "Validator",
                            "datapoint": "type",
                            "stix-type": "x-matterbot-type",
                            "value": "LongString",
                        },
                    ],
                }
            )
            continue

        # String
        if isinstance(param, String):
            data["responses"].append(
                {
                    "paragraph": "String input",
                    "preamble": "Input was validated as a simple String.",
                    "data": [
                        {
                            "category": "Text",
                            "subcategory": "String",
                            "datapoint": "value",
                            "stix-type": "x-matterbot-string",
                            "value": str(param),
                        },
                        {
                            "category": "Debug",
                            "subcategory": "Validator",
                            "datapoint": "type",
                            "stix-type": "x-matterbot-type",
                            "value": "String",
                        },
                    ],
                }
            )
            continue

        # Fallback
        data["responses"].append(
            {
                "paragraph": "Unknown input",
                "preamble": (
                    f"Received an unexpected parameter type: {type(param).__name__}."
                ),
                "data": [
                    {
                        "category": "Unknown",
                        "subcategory": "",
                        "datapoint": "value",
                        "stix-type": "x-matterbot-unknown",
                        "value": str(param),
                    }
                ],
            }
        )

    return data