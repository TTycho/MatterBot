#!/usr/bin/env python3

from core.typevalidators import ASN
from core import helpers
from commands.asnwhois import defaults as settings


def search(parameters: list[ASN], options: str, *args, **kwargs) -> dict:  # noqa: ARG001
    """Get ASN details and geolocation for one or more ASNs."""

    result: dict = {
        'module': __package__,
        'source': 'caida-asrank',
        'responses': [],
        'message': '',
    }

    for value in parameters:
        asn_number = value.removeprefix("AS")

        asn_url = settings.APIURL['asnwhois']['url'] + asn_number
        asn_response = helpers.api_get_with_auth_token(
            asn_url,
            None,
            headers={"Accept": 'application/json'},
        )

        data = asn_response.get('data', {})
        asn_data = data.get('asn')

        if asn_data is None:
            result['responses'].append({
                'paragraph': 'ASN details',
                'preamble': f"ASN {asn_number} does not exist; please verify the number.",
                'data': [],
            })
            continue

        name = asn_data.get('asnName')
        source = asn_data.get('source')
        country = (asn_data.get('country') or {}).get('iso')
        degree = asn_data.get('asnDegree') or {}
        peers = degree.get('peer')
        providers = degree.get('provider')
        latitude = asn_data.get('latitude')
        longitude = asn_data.get('longitude')

        # geodata = {}
        # if latitude is not None and longitude is not None:
        #     osm_url = (
        #         f"{settings.APIURL['osmdata']['url']}lat={latitude}&lon={longitude}&format=json"
        #     )
        #     geodata = helpers.api_get_with_auth_token(
        #         osm_url,
        #         None,
        #         headers={"Accept": settings.CONTENTTYPE},
        #     )

        # address = geodata.get('display_name') if isinstance(geodata, dict) else None

        preamble_parts = [value]
        if name:
            preamble_parts.append(f"({name})")
        if country:
            preamble_parts.append(f"[{country}]")
        preamble = ' '.join(preamble_parts)

        rows: list[dict] = []

        rows.append({
            'category': 'Network',
            'subcategory': 'Autonomous system',
            'stix-type': 'autonomous-system',
            'datapoint': 'asn',
            'value': asn_number,
        })

        if name:
            rows.append({
                'category': 'Network',
                'subcategory': 'Autonomous system',
                'stix-type': 'autonomous-system',
                'datapoint': 'name',
                'value': name,
            })

        if country:
            rows.append({
                'category': 'Network',
                'subcategory': 'Geolocation',
                'stix-type': 'location',
                'datapoint': 'country',
                'value': country,
            })

        if latitude is not None:
            rows.append({
                'category': 'Network',
                'subcategory': 'Geolocation',
                'stix-type': 'location',
                'datapoint': 'lat',
                'value': latitude,
            })

        if longitude is not None:
            rows.append({
                'category': 'Network',
                'subcategory': 'Geolocation',
                'stix-type': 'location',
                'datapoint': 'lon',
                'value': longitude,
            })

        # if address:
        #     rows.append({
        #         'category': 'Network',
        #         'subcategory': 'Geolocation',
        #         'stix-type': 'location',
        #         'datapoint': 'address',
        #         'value': address,
        #     })

        if peers is not None:
            rows.append({
                'category': 'Network',
                'subcategory': 'Peers',
                'stix-type': 'x-metric',
                'datapoint': 'peer-count',
                'value': peers,
            })

        if providers is not None:
            rows.append({
                'category': 'Network',
                'subcategory': 'Providers',
                'stix-type': 'x-metric',
                'datapoint': 'provider-count',
                'value': providers,
            })

        if source:
            rows.append({
                'category': 'Network',
                'subcategory': 'Autonomous system',
                'stix-type': 'autonomous-system',
                'datapoint': 'source',
                'value': source,
            })

        result['responses'].append({
            'paragraph': 'ASN details',
            'preamble': preamble,
            'data': rows,
        })

    return result


