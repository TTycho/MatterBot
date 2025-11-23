"""Formatters for module results.

Provides helpers to convert structured module output (source/responses/data)
into the normalized {'messages': [...]} form consumed by the rest of the bot.
"""
from typing import Dict, Any


def format_as_tables(result: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a structured module result into a dict with 'messages' key.

    Expected input shape:
    {
      'source': 'service name',
      'responses': [ { 'preamble': '...', 'paragraph': '...', 'data': [ ... ] }, ... ]
    }

    Output:
    { 'messages': [ { 'text': '...'}, ... ] }
    """
    msgs = []
    source = result.get('source', '')
    for resp in result.get('responses', []):
        parts = []
        preamble = resp.get('preamble')
        paragraph = resp.get('paragraph')
        if preamble:
            parts.append(preamble)
        if paragraph:
            parts.append(f"*{paragraph}*")

        # Collect datapoints
        for data in resp.get('data', []):
            category = data.get('category', '')
            subcategory = data.get('subcategory', '')
            datapoint = data.get('datapoint') or data.get('name') or ''
            value = data.get('value', '')
            stix = data.get('stix-type') or data.get('stix_type') or ''

            # Build a compact category/subcategory representation
            catpart = ''
            if category and subcategory:
                catpart = f"{category}/{subcategory}"
            elif category:
                catpart = category
            elif subcategory:
                catpart = subcategory

            line = f"- {datapoint}: {value}"
            if catpart:
                line += f" ({catpart})"
            if stix:
                line += f" [{stix}]"
            parts.append(line)

        body = "\n".join(parts).strip()
        header = f"** {source} **" if source else ''
        text = header + ("\n\n" + body if body else "")
        msgs.append({'text': text})

    # Return structure:
    # {
    #   'messages': [
    #       { 'text': '<string>' },   # each message is a dict containing at least a 'text' string
    #       ...
    #   ]
    # }
    # Callers iterate over result['messages'] and render/send each message's 'text'.
    return {'messages': msgs}

