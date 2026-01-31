# asnwhois

Lookup ASN details and approximate geolocation using CAIDA ASRank and OpenStreetMap Nominatim.

## API documentation

- CAIDA ASRank ASN API: https://api.asrank.caida.org/
- Example ASN endpoint: https://api.asrank.caida.org/v2/restful/asns/1
- OpenStreetMap Nominatim reverse geocoding: https://nominatim.org/release-docs/latest/api/Reverse/

## Module documentation

### Subcommands

- `asn` (default): Look up information about an Autonomous System Number.

### Parameters

- `asn`: An Autonomous System Number, validated with the ASN type from `core/typevalidators`.

### Example usage

- `@asn 15169`
- `@asnwhois 1`
