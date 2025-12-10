#!/usr/bin/env python3
import re
import logging
import validators
import tldextract  # new import

__all__ = [
    "Domain", "IPv4", "IPv6", "URL", "Hostname", "MACAddress",
    "Email", "BTCAddress", "MD5", "SHA1", "SHA256", "SHA512",
    "UUID", "ASN", "String", "LongString"
]


# -- string-like validators (subclass str so instances behave as strings) --

class Domain(str):
    def __new__(cls, value: str) -> "Domain":
        """
        Validate as a domain-like string and normalize to the "private" part:

        - 'www.example.com'      -> 'example.com'
        - 'example.co.uk'        -> 'example.co.uk'   (unchanged)
        - 'www.mysite.blogspot.com' -> 'mysite.blogspot.com'
        """

        raw = value.strip().lower()

        # Basic validation: is there a dot in the raw string?
        if "." not in raw:
            raise ValueError(f"No dot in {raw}.")

        clean = raw.replace('[.]', '.').replace('hxxp','http').lower()

        # Use tldextract to get the registered (private) domain
        extracted = tldextract.extract(clean, include_psl_private_domains=True)
        registered = extracted.top_domain_under_public_suffix
        if not registered:
            raise ValueError(f"Not a possible registered domain: {clean}")
        return str.__new__(cls, registered)


class IPv4(str):
    def __new__(cls, value: str) -> "IPv4":
        v = value.strip()
        if not validators.ipv4(v):
            raise ValueError(f"Invalid IPv4 address: {value}")
        return str.__new__(cls, v)


class IPv6(str):
    def __new__(cls, value: str) -> "IPv6":
        v = value.strip()
        if not validators.ipv6(v):
            raise ValueError(f"Invalid IPv6 address: {value}")
        return str.__new__(cls, v)


class URL(str):
    def __new__(cls, value: str) -> "URL":
        raw = value.strip()

        # Basic validation: is there a dot in the raw string?
        if "." not in raw:
            raise ValueError(f"No dot in {raw}.")

        clean = raw.replace('[.]', '.').replace('hxxp','http')

        # Use tldextract to get the registered (private) domain
        extracted = tldextract.extract(clean)
        registered = extracted.top_domain_under_public_suffix
        if not registered:
            raise ValueError(f"Not a URL with a possible fully qualified domain name: {raw}")
        return str.__new__(cls, clean)


class Hostname(str):
    def __new__(cls, value: str) -> "Hostname":
        raw = value.strip().lower()

        # Basic validation: is there a dot in the raw string?
        if "." not in raw:
            raise ValueError(f"No dot in {raw}.")

        clean = raw.replace('[.]', '.').replace('hxxp','http').lower()

        # Use tldextract to get the registered (private) domain
        extracted = tldextract.extract(clean)
        registered = extracted.fqdn
        if not registered:
            raise ValueError(f"Not a possible fully qualified domain name: {raw}")
        return str.__new__(cls, registered)


class MACAddress(str):
    def __new__(cls, value: str) -> "MACAddress":
        v = value.strip()
        if not validators.mac_address(v):
            raise ValueError(f"Invalid MAC address: {value}")
        return str.__new__(cls, v)


class Email(str):
    def __new__(cls, value: str) -> "Email":
        v = value.strip()

        # Basic validation: is there a dot in the raw string?
        if "@" not in v:
            raise ValueError(f"No @ symbol in {v}.")

        if not validators.email(v):
            raise ValueError(f"Invalid email address: {value}")
        return str.__new__(cls, v)


class BTCAddress(str):
    def __new__(cls, value: str) -> "BTCAddress":
        v = value.strip()
        if not validators.btc_address(v):
            raise ValueError(f"Invalid Bitcoin address: {value}")
        return str.__new__(cls, v)


# -- hash-like validators (hex strings) --

_HEX_RE = re.compile(r"^[A-Fa-f0-9]+$")


class MD5(str):
    def __new__(cls, value: str) -> "MD5":
        v = value.strip()
        if not (_HEX_RE.fullmatch(v) and len(v) == 32):
            raise ValueError(f"Invalid MD5 hash: {value}")
        return str.__new__(cls, v)


class SHA1(str):
    def __new__(cls, value: str) -> "SHA1":
        v = value.strip()
        if not (_HEX_RE.fullmatch(v) and len(v) == 40):
            raise ValueError(f"Invalid SHA1 hash: {value}")
        return str.__new__(cls, v)


class SHA256(str):
    def __new__(cls, value: str) -> "SHA256":
        v = value.strip()
        if not (_HEX_RE.fullmatch(v) and len(v) == 64):
            raise ValueError(f"Invalid SHA256 hash: {value}")
        return str.__new__(cls, v)


class SHA512(str):
    def __new__(cls, value: str) -> "SHA512":
        v = value.strip()
        if not (_HEX_RE.fullmatch(v) and len(v) == 128):
            raise ValueError(f"Invalid SHA512 hash: {value}")
        return str.__new__(cls, v)


class UUID(str):
    def __new__(cls, value: str) -> "UUID":
        v = value.strip()
        if not validators.uuid(v):
            raise ValueError(f"Invalid UUID: {value}")
        return str.__new__(cls, v)

'''A longstring can be multiple words separated by spaces or a single string.'''
class LongString(str):
    def __new__(cls, value: str) -> "LongString":
        if not isinstance(value, str):
            raise ValueError(f"Somehow this is not a string: {value}")
        v = value.strip()
        if not ' ' in v:
            raise ValueError("LongString requires multiple words; use String for single words.")
        return str.__new__(cls, v)

'''This is a single word.'''
class String(str):
    def __new__(cls, value: str) -> "LongString":
        if not isinstance(value, str):
            raise ValueError(f"Somehow this is not a string: {value}")
        v = value.strip()
        if ' ' in v:
            raise ValueError("This is not a simple string.")
        return str.__new__(cls, v)


class ASN(str):
    """
    Normalize and validate ASN strings like 'AS1234', 'ASN1234' or '1234'.
    Stored as 'AS<number>'.
    """
    def __new__(cls, value: str) -> "ASN":
        num = value.strip().upper()
        # start with the raw value, strip known prefixes (check longer prefix first)
        if num.startswith("ASN"):
            num = num[3:]
        elif num.startswith("AS"):
            num = num[2:]
        # now ensure what's left is all digits
        if not num.isdigit():
            raise ValueError(f"Expecting just numbers, not {value}")
        n = int(num)
        # reasonable range check
        if not (1000 <= n <= 500000):
            raise ValueError(f"ASN out of expected range: {n}")
        return str.__new__(cls, f"AS{n}")
