import logging
from typing import get_origin, get_args
import types as _types
import requests
from typing import Optional, Dict, Any, Tuple
import typing  # needed for expand_annotation's Literal handling
import time
import inspect
from typing import TypedDict


class BearerAuthData(TypedDict, total=False):
    """
    Minimal auth payload for bearer token retrieval.
    Must contain at least 'username' and 'password'; callers can add more fields.
    """
    username: str
    password: str
    # additional optional fields like 'grant_type', 'client_id', 'scope', etc. are allowed


# Simple in-memory bearer token cache:
# { cache_key: {"access_token": str, "expires_at": float} }
_BEARER_TOKEN_CACHE: Dict[str, Dict[str, Any]] = {}


def get_bearer_token(
    token_url: str,
    auth_data: BearerAuthData,
    *,
    cache_key: Optional[str] = None,
    extra_headers: Optional[Dict[str, str]] = None,
    method: str = "POST",
    token_field: str = "access_token",
    expires_in_field: str = "expires_in",
    default_ttl: int = 3600,
) -> str:
    """
    Obtain (and cache) a bearer token from an authorization endpoint.

    - token_url: URL of the token endpoint.
    - auth_data: payload sent to the endpoint (e.g. username/password, client_id/secret, grant_type).
    - cache_key: cache bucket name; if None, no caching is performed.
    - extra_headers: optional headers for the token request.
    - method: HTTP method, usually 'POST' (can be 'GET' for some APIs).
    - token_field: JSON key containing the access token.
    - expires_in_field: JSON key containing token lifetime in seconds.
    - default_ttl: used if the response has no expires_in field.
    """
    if cache_key:
        cached = _BEARER_TOKEN_CACHE.get(cache_key)
        now = time.time()
        if cached and cached.get("expires_at", 0) > now:
            logging.debug(
                "Reusing cached bearer token for cache_key '%s' (expires_at=%s)",
                cache_key,
                cached.get("expires_at"),
            )
            return cached["access_token"]

    headers = {"Accept": "application/json"}
    if extra_headers:
        headers.update(extra_headers)

    try:
        logging.debug(f"Requesting bearer token from: {token_url} (cache_key={cache_key})")
        if method.upper() == "POST":
            resp = requests.post(token_url, data=auth_data, headers=headers)
        else:
            resp = requests.get(token_url, params=auth_data, headers=headers)
    except requests.exceptions.Timeout:
        raise TimeoutError("Token request timed out")
    except requests.exceptions.TooManyRedirects:
        raise RuntimeError("Too many redirects while requesting token")
    except requests.exceptions.RequestException as e:
        raise ConnectionError(f"Connection error while requesting token: {e}")

    if not (200 <= resp.status_code < 300):
        raise RuntimeError(f"Token endpoint returned {resp.status_code}: {resp.text}")

    try:
        body = resp.json()
    except ValueError:
        raise ValueError("Token endpoint did not return valid JSON")

    if token_field not in body:
        raise RuntimeError(f"Token field '{token_field}' not found in response: {body}")

    access_token = body[token_field]
    ttl = int(body.get(expires_in_field, default_ttl))
    expires_at = time.time() + max(ttl - 30, 0)  # small safety margin

    if cache_key:
        _BEARER_TOKEN_CACHE[cache_key] = {
            "access_token": access_token,
            "expires_at": expires_at,
        }
        logging.debug(
            "Stored new bearer token for cache_key '%s' with expiry at %s",
            cache_key,
            expires_at,
        )

    return access_token


def api_get_auth_token(url: str, token: str, headers: Optional[Dict[str, str]] = None) -> Any:
    """
    Perform a GET request with a custom 'Token' style Authorization header.

    Example:
        Authorization: Token <token>
    """
    if headers:
        base_headers = headers
    else:
        base_headers: Dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Token {token}",
        }
    
    try:
        logging.debug(f"GET (auth token): {url}")
        resp = requests.get(url, headers=base_headers)
    except requests.exceptions.Timeout:
        raise TimeoutError("Request timed out")
    except requests.exceptions.TooManyRedirects:
        raise RuntimeError("Too many redirects")
    except requests.exceptions.RequestException as e:
        raise ConnectionError(f"Connection error: {e}")  # to be caught by caller

    if 200 <= resp.status_code < 300:
        try:
            return resp.json()
        except ValueError:
            raise ValueError("Response is not valid JSON")
        except Exception as e:
            raise RuntimeError(f"Error parsing JSON response: {e}")
    raise RuntimeError(f"Unexpected status code {resp.status_code}: {resp.text}")


def api_get_bearer_token(
    token_url: str,
    auth_data: BearerAuthData,
    url: str,
    headers: Optional[Dict[str, str]] = None,
) -> Any:
    """
    Obtain (and cache) a bearer token using the given auth_data, then perform
    a GET request with a 'Bearer' Authorization header to the specified URL.

    - token_url: URL of the token/authorization endpoint.
    - auth_data: payload sent to the token endpoint; must contain at least
                 'username' and 'password', but may include extra fields
                 (e.g. grant_type, client_id, scope, etc.).
    - url: protected resource URL to GET.
    - headers: additional headers for the resource request (merged with Authorization).

    The token is cached per-calling module by default.
    """
    # Determine caller module name to use as cache key
    stack = inspect.stack()
    caller_frame = stack[1][0] if len(stack) > 1 else None
    mod = inspect.getmodule(caller_frame) if caller_frame else None
    cache_key = getattr(mod, "__name__", "unknown_module")
    token =  _BEARER_TOKEN_CACHE.get(cache_key, {}).get("access_token")

    # Let the caller decide the exact auth_data; we just pass it through
    

    
    base_headers: Dict[str, str] = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
    }
    if headers:
        base_headers.update(headers)

    try:
        logging.debug(f"GET (bearer): {url}")
        resp = requests.get(url, headers=base_headers)
        if 200 <= resp.status_code < 300:
            return resp.json()
        elif resp.status_code == 401:
            # Token might be expired; get a new one and retry once
            token = get_bearer_token(
                token_url,
                auth_data,
                cache_key=cache_key,
            )
        base_headers["Authorization"] = f"Bearer {token}"
        logging.debug(f"Retrying GET (bearer) after obtaining new token: {url}")
        resp = requests.get(url, headers=base_headers)
    except requests.exceptions.Timeout:
        raise TimeoutError("Request timed out")
    except requests.exceptions.TooManyRedirects:
        raise RuntimeError("Too many redirects")
    except requests.exceptions.RequestException as e:
        raise ConnectionError(f"Connection error: {e}")
    except ValueError:
        raise ValueError("Response is not valid JSON")
    except Exception as e:
        raise RuntimeError(f"Error parsing JSON response: {e}")
    raise RuntimeError(f"Unexpected status code {resp.status_code}: {resp.text}")


def api_get_basic_auth(
    url: str,
    username: str,
    password: str,
    headers: Optional[Dict[str, str]] = None,
) -> Any:
    """
    Perform a GET request using HTTP Basic authentication.
    """
    base_headers: Dict[str, str] = {
        "Accept": "application/json",
    }
    if headers:
        base_headers.update(headers)

    try:
        logging.debug(f"GET (basic auth): {url}")
        resp = requests.get(url, headers=base_headers, auth=(username, password))
    except requests.exceptions.Timeout:
        raise TimeoutError("Request timed out")
    except requests.exceptions.TooManyRedirects:
        raise RuntimeError("Too many redirects")
    except requests.exceptions.RequestException as e:
        raise ConnectionError(f"Connection error: {e}")

    if 200 <= resp.status_code < 300:
        try:
            return resp.json()
        except ValueError:
            raise ValueError("Response is not valid JSON")
        except Exception as e:
            raise RuntimeError(f"Error parsing JSON response: {e}")

    raise RuntimeError(f"Unexpected status code {resp.status_code}: {resp.text}")


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