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


# ...existing code...
import typing
import inspect

from typing import get_type_hints, get_origin, get_args
from core import typevalidators

def validatetype(modules, module_name, subcommand, value):
    pass
    return True

def extract_allowed_literals_from_param(func, param_name='command'):
    """
    Given a function object (or unbound method) `func`, inspect the annotation for parameter
    `param_name`. If it's a TypedDict with a 'parameters' field that is List[Literal[...]]
    or directly List[Literal[...]], return a list of literal string choices, otherwise None.
    """
    try:
        module = inspect.getmodule(func) or {}
        hints = typing.get_type_hints(func, globalns=getattr(module, '__dict__', {}))
    except Exception:
        hints = {}
    ann = hints.get(param_name)
    if ann is None:
        return None

    # If annotation is a TypedDict class, inspect its 'parameters' field
    if hasattr(ann, '__annotations__') or getattr(ann, '__total__', None) is not None:
        try:
            td_hints = typing.get_type_hints(ann, globalns=getattr(module, '__dict__', {}))
            ann = td_hints.get('parameters', ann)
        except Exception:
            pass

    # Expect ann to be something like List[Literal[...]] or Literal[...]
    origin = typing.get_origin(ann)
    # if it's a container like List[T], drill into T
    if origin in (list, typing.List):
        inner = typing.get_args(ann)
        if not inner:
            return None
        ann = inner[0]

    # If ann is Literal[...] return its args
    if typing.get_origin(ann) is typing.Literal:
        return list(typing.get_args(ann))

    # If ann itself is Literal without origin handling (fallback)
    try:
        if hasattr(ann, '__args__') and ann.__origin__ is typing.Literal:
            return list(ann.__args__)
    except Exception:
        pass

    return None

# Example usage inside your loop where you determine allowed_types:
# func = self.commands[module_name]['commands'].query  # or the function object you want to inspect
# literals = extract_allowed_literals_from_param(func, 'command')
# if literals:
#     allowed_types = literals
# else:
#     allowed_types = self.commands[module_name]['settings']['EXPECT']['subcommands'][messages[module_name]['subcommand']]['types']

import typing
from typing import get_origin, get_args
import types as _types

def expand_annotation(ann):
    """Return a set of concrete annotation members (types or literal values).
    Handles: T | U (PEP 604), typing.Union, List[T], Tuple[T,...], typing.Literal, nested combinations.
    """
    members = set()
    if ann is None:
        return members

    to_origin = get_origin(ann)
    # typing.Union or PEP 604 union (types.UnionType on 3.10+)
    union_alt = getattr(_types, 'UnionType', None)
    if to_origin is typing.Union or to_origin is union_alt:
        for a in get_args(ann):
            members.update(expand_annotation(a))
        return members

    # Container types like List[T], Tuple[T,...], Set[T]
    if to_origin in (list, tuple, set):
        args = get_args(ann)
        if args:
            members.update(expand_annotation(args[0]))
        return members

    # Literal[...] -> return literal values
    if to_origin is getattr(typing, 'Literal', None):
        for v in get_args(ann):
            members.add(v)
        return members

    # Fallback: single annotation (type or value)
    members.add(ann)
    return members


from typing import Any, Iterable, Tuple

def expects(*types):
    """Decorator to attach expected parameter types to a command function.
    Usage: @expects(Domain, IPv4) or @expects('mode1','mode2')
    """
    def deco(func):
        func._expected_types = types
        return func
    return deco

def try_coerce_to_expected(token: str, expected: Iterable[Any]) -> Tuple[Any, Any]:
    """Try to coerce `token` into one of the items in `expected`.
    Returns (coerced_value, matched_expected) or (None, None) if no match.
    Rules:
    - If expected item is a class that subclasses str (validator classes): try to construct it.
    - If expected item is a literal (str/int/...): compare directly (case-insensitive for strings).
    - Fallback: use detect_type to match class names (compare lowercase).
    """
    if not expected:
        return None, None

    # normalize expected to a sequence
    for exp in expected:
        # literal constants (strings/ints/...)
        if isinstance(exp, (str, int, float, bool)):
            if isinstance(exp, str):
                if token.lower() == exp.lower():
                    return token, exp
            else:
                if str(exp) == token:
                    return token, exp
            continue

        # validator classes that subclass str (Domain, IPv4, ...)
        if isinstance(exp, type):
            try:
                if isinstance(token, exp):
                    return token, exp
                coerced = exp(token)   # may raise ValueError on invalid
                return coerced, exp
            except Exception:
                # fallback: compare detected type name
                detected = typevalidatorsdetect_type(token)
                name = getattr(exp, '__name__', str(exp)).lower()
                if detected and detected == name.replace('_', ''):  # tolerate small name diffs
                    return token, exp
                continue

        # fallback compare stringified expected
        try:
            if str(exp).lower() == token.lower():
                return token, exp
        except Exception:
            pass

    # nothing matched
    return None, None
