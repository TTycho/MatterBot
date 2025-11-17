#!/usr/bin/env python3

import logging
import validators

def checktype(word):
    """
    Check the type of a word using the validators package.
    Args:
        word (str): The word to check.

    Returns:
        str: The matched type or None if no match.
    """
    # Check for IPv4 address
    if validators.ipv4(word):
        if validators.ipv4(word, private=True):
            logging.debug("This is a private IPv4 address.")
            return 'private'
        elif validators.ipv4(word, strict=True):
            logging.debug("This is a CIDR notation.")
            return 'cidr'
        else:
            logging.debug("This is a public IPv4 address.")
            return 'ipv4'

    # Check for IPv6 address
    if validators.ipv6(word):
        logging.debug("This is an IPv6 address.")
        return 'ipv6'

    # Check for URL
    if validators.url(word):
            logging.debug("This is a URL.")
            return 'url'

    # Check for domain
    if validators.domain(word):
        logging.debug("This is a domain.")
        return 'domain'

    # Check for hostname
    if validators.hostname(word):
        logging.debug("This is a hostname.")
        return 'hostname'
    # Check for MAC address
    if validators.mac_address(word):
        logging.debug("This is a MAC address.")
        return 'mac_address'


    # Check for email address
    if validators.email(word):
        logging.debug("This is an email address.")
        return 'email'

    # Check for MD5 hash
    if validators.md5(word):
        logging.debug("This is an MD5 hash.")
        return 'md5_hash'

    # Check for SHA1 hash
    if validators.sha1(word):
        logging.debug("This is a SHA1 hash.")
        return 'sha1_hash'

    # Check for SHA256 hash
    if validators.sha256(word):
        logging.debug("This is a SHA256 hash.")
        return 'sha256_hash'

    # Check for SHA512 hash
    if validators.sha512(word):
        logging.debug("This is a SHA512 hash.")
        return 'sha512_hash'
    # Check for UUID
    if validators.uuid(word):
        logging.debug("This is a UUID.")
        return 'uuid'

    # Check for ASN
    if word.isdigit() or word.startswith("AS") or word.startswith("ASN"):
        number = word[2:] if word.startswith("AS") else word[3:] if word.startswith("ASN") else word if word.isdigit() else None
        if number.isdigit() and 1000 <= int(number) <= 500000:
            logging.debug("This is possibly an ASN.")
            return 'asn'

    # Check for Bitcoin address
    if validators.btc_address(word):
        logging.debug("This is a Bitcoin address.")
        return 'btc'

    # If no type matches, return None
    logging.debug(f"No matching type found for word: {word}")
    return None

