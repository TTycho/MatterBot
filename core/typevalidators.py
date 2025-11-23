#!/usr/bin/env python3
import re
import logging
from typing import Optional

import validators

__all__ = [
    "Domain", "IPv4", "IPv6", "URL", "Hostname", "MACAddress",
    "Email", "BTCAddress", "MD5", "SHA1", "SHA256", "SHA512",
    "UUID", "ASN", "detect_type",
]


# -- string-like validators (subclass str so instances behave as strings) --

class Domain(str):
    def __new__(cls, value: str) -> "Domain":
        v = value.strip().lower()
        if not validators.domain(v):
            raise ValueError(f"Invalid domain: {value}")
        return str.__new__(cls, v)


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
        v = value.strip()
        if not validators.url(v):
            raise ValueError(f"Invalid URL: {value}")
        return str.__new__(cls, v)


class Hostname(str):
    def __new__(cls, value: str) -> "Hostname":
        v = value.strip().lower()
        if not validators.hostname(v):
            raise ValueError(f"Invalid hostname: {value}")
        return str.__new__(cls, v)


class MACAddress(str):
    def __new__(cls, value: str) -> "MACAddress":
        v = value.strip()
        if not validators.mac_address(v):
            raise ValueError(f"Invalid MAC address: {value}")
        return str.__new__(cls, v)


class Email(str):
    def __new__(cls, value: str) -> "Email":
        v = value.strip()
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


class LongString(str):
    def __new__(cls, value: str) -> "LongString":
        v = value
        if not isinstance(value, str):
            raise ValueError(f"Somehow this is not a string: {value}")
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


# -- helper that mirrors core.helpers.checktype (prefer these classes) --

def detect_type(word: str) -> Optional[str]:
    """
    Try to detect type using Validators classes and validators library.
    Returns the same type strings used in core.helpers.checktype (e.g. 'ipv4','private','cidr','domain',...).
    """
    w = word.strip()
    try:
        # IPv4 with special checks for private / cidr
        if validators.ipv4(w):
            if validators.ipv4(w, private=True):
                logging.debug("This is a private IPv4 address.")
                return "private"
            # validators.ipv4(strict=True) returns True for e.g. CIDR? replicate original code
            if validators.ipv4(w, strict=True):
                logging.debug("This is a CIDR notation.")
                return "cidr"
            logging.debug("This is a public IPv4 address.")
            return "ipv4"

        if validators.ipv6(w):
            logging.debug("This is an IPv6 address.")
            return "ipv6"

        if validators.url(w):
            logging.debug("This is a URL.")
            return "url"

        if validators.domain(w):
            logging.debug("This is a domain.")
            return "domain"

        if validators.hostname(w):
            logging.debug("This is a hostname.")
            return "hostname"

        if validators.mac_address(w):
            logging.debug("This is a MAC address.")
            return "mac_address"

        if validators.email(w):
            logging.debug("This is an email address.")
            return "email"

        # hash checks using regex
        if _HEX_RE.fullmatch(w):
            if len(w) == 32:
                logging.debug("This is an MD5 hash.")
                return "md5_hash"
            if len(w) == 40:
                logging.debug("This is a SHA1 hash.")
                return "sha1_hash"
            if len(w) == 64:
                logging.debug("This is a SHA256 hash.")
                return "sha256_hash"
            if len(w) == 128:
                logging.debug("This is a SHA512 hash.")
                return "sha512_hash"

        if validators.uuid(w):
            logging.debug("This is a UUID.")
            return "uuid"

        # ASN heuristic
        num = None
        up = w.upper()
        if up.startswith("AS"):
            num = up[2:]
        elif up.startswith("ASN"):
            num = up[3:]
        elif w.isdigit():
            num = w
        if num and num.isdigit():
            n = int(num)
            if 1000 <= n <= 500000:
                logging.debug("This is possibly an ASN.")
                return "asn"

        if validators.btc_address(w):
            logging.debug("This is a Bitcoin address.")
            return "btc"
    except Exception:
        logging.exception("Error during detect_type")

    logging.debug(f"No matching type found for word: {word}")
    return None