from typing import Dict, Any
"""Formatters for module results.

Provides helpers to convert structured module output (source/responses/data)
into the normalized {'messages': [...]} form consumed by the rest of the bot.
"""


"""
Data is received from the modules in the dict format:

{
    "source":"full service name",
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
    ]
}

No hit:
{
    "source":"provider",
    "responses": []
}

category, datapoint and value are taken from the source. Only stix-type
is the same across modules for values of the same type.

Eventually converts to a message text and possibly an attachment.
The text can have multiple paragraph with a short introduction of the source.

Output data in the format structure:

module_name
- service name
- preamble
    - paragraph
        - data set
            - category
                - datapoint
                - stix-type
                    - value
Can be converted to output:

** Service name **
|*Indicator 1*|            |
|-------------|------------|
|IP address   | 1.1.1.1    |
|Comment      | Context    |

|*Indicator 2*|            |
|-------------|------------|
|IP address   | 1.1.1.1    |
|Comment      | Context    |


"""

def format_as_tables(result: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a structured module result into a dict with 'messages' key.

    Produces:
    - A markdown table in the message 'text' (fallback method)
    - A Mattermost-style attachment (props.attachments) that contains fields:
      * Category/Subcategory rows as full-width (short: False)
      * Datapoint/value rows as short fields (short: True) so they render side-by-side

    This gives both a readable table and a column-like layout via attachment fields.
    """
    def _escape_cell(x):
        return str(x).replace('|', r'\|') if x is not None else ''

    msgs = []
    source = result.get('source', '')
    author = result.get('module', 'matterbot')

    for resp in result.get('responses', []):
        parts = []
        preamble = resp.get('preamble')
        paragraph = resp.get('paragraph')
        if preamble:
            parts.append(preamble)
        if paragraph:
            parts.append(f"*{paragraph}*")

        data_rows = []
        # build attachment fields in parallel to the markdown table
        fields = []
        last_cat_sub = (None, None)

        for data in resp.get('data', []):
            category = data.get('category', '') or ''
            subcategory = data.get('subcategory', '') or ''
            datapoint = data.get('datapoint') or data.get('name') or ''
            value = data.get('value', '')
            doc = data.get('doc', '')

            # stix = data.get('stix-type') or data.get('stix_type') or ''

            # markdown table row
            row = "| {} | {} |".format(
                # _escape_cell(category),
                # _escape_cell(subcategory),
                _escape_cell(datapoint),
                _escape_cell(value),
                # _escape_cell(stix),
            )
            data_rows.append(row)

            # Add a full-width field when category/subcategory changes to act as a section header
            cat_sub = (category, subcategory)
            if cat_sub != last_cat_sub:
                header_title = category # subcategory if subcategory else category
                header_sub = f" - {subcategory}" if subcategory else ""
                fields.append({
                    "short": False,
                    "title": f"{header_title}{header_sub}",
                    "value": doc
                })
                last_cat_sub = cat_sub

            # Add the datapoint as a short field (title) with the value as content so pairs render side-by-side
            value_display = str(value) if value is not None else ""
            # if stix:
            #     value_display = f"{value_display} ({stix})"
            fields.append({
                "short": True,
                "title": str(datapoint) or "(value)",
                "value": value_display
            })

        # build markdown table (fallback / visible in message body)
        if data_rows:
            table_header = "| Category | Subcategory | Datapoint | Value | STIX |"
            table_sep = "|---|---|---|---|---|"
            table_md = "\n".join([table_header, table_sep] + data_rows)
            parts.append(table_md)
        else:
            parts.append("_no data returned_")

        body = "\n\n".join(parts).strip()
        source_header = f"** {source} **" if source else ""
        text = source_header + ("\n\n" + body if body else "")

        # Attachment: include preamble/paragraph in attachment text and fields for column-like layout
        attachment = {
            "fallback": text,
            "author_name": author,
            "title": paragraph or source or "Result",
            "text": preamble or "",
            "fields": fields
        }

        msgs.append({
            # "text": text,
            "props": {
                "attachments": [attachment]
            }
        })

    return {"messages": msgs}

