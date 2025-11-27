"""
This module provides a debug command that shows how MatterBot validates and normalizes
different input types.

Each validated parameter is returned as a separate response, indicating:
- which MatterBot type it was validated as
- a STIX type that best matches the validator
- the normalized value received by the command
"""
from typing import List
from core.typevalidators import String, LongString, Domain, IPv4, IPv6, Hostname, URL, Email, ASN
# if some of these do not exist in core/typevalidators.py, remove them from the import and from the union below


SERVICE_NAME = "Debug Module"


def test(
    parameters: List[String | LongString | Domain | IPv4 | IPv6 | Hostname | URL | Email | ASN], 
    options: str, *args, **kwargs) -> dict:
    """
    Debug command that accepts many different input types and reports:

    - which MatterBot type the input was validated as
    - the matching STIX type (where applicable)
    - the normalized value

    This is useful to see how the core typevalidators behave.
    """
    data = {
        "module": __package__,
        "source": SERVICE_NAME,
        "responses": [],
    }

    # Map validator classes to human-readable and STIX types
    type_map = {
        String: ("String", "x-matterbot-string"),
        LongString: ("LongString", "x-matterbot-string"),
        Domain: ("Domain", "domain-name"),
        IPv4: ("IPv4", "ipv4-addr"),
        IPv6: ("IPv6", "ipv6-addr"),
        Hostname: ("Hostname", "domain-name"),
        URL: ("URL", "url"),
        Email: ("Email", "email-addr"),
    }

    if not parameters:
        # Explain what this command does if no parameters are given
        data["responses"].append(
            {
                "paragraph": "debug",
                "preamble": (
                    "This command accepts many different input types and shows which "
                    "validator and STIX type are used for each value."
                ),
                "data": [],
            }
        )
        return data

    for idx, param in enumerate(parameters):
        # Determine which validator class matched
        matched_cls = None
        for cls in type_map:
            if isinstance(param, cls):
                matched_cls = cls
                break

        if matched_cls is None:
            # Fallback if something unexpected slipped through
            type_name = type(param).__name__
            stix_type = "x-matterbot-unknown"
        else:
            type_name, stix_type = type_map[matched_cls]

        response = {
            "paragraph": f"Parameter {idx + 1}",
            "preamble": f"Validated as {type_name} ({stix_type}).",
            "data": [],
        }

        # Put the validated / normalized value in the data part
        response["data"].append(
            {
                "category": type_name,
                "subcategory": "",
                "datapoint": "value",
                "stix-type": stix_type,
                "value": str(param),
            }
        )

        data["responses"].append(response)

    return data