"""Minimal EVM JSON-RPC client for the Mordred extension wallet (SPEC §5.3).

Used to fill missing transaction fields (nonce / gas / fees / chainId) and to
broadcast the signed raw transaction. Honors the gateway's configured proxy
(Tor via ``mordred_network``) so RPC egress follows the same path as the rest
of Hermes — the extension itself never talks to an RPC node.

Synchronous (``requests``); callers invoke it from a thread executor.
"""

from __future__ import annotations

import json
import socket
import ssl
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any
from urllib.parse import SplitResult, urlsplit

# Public fallback endpoints; users should set their own via wallet.json `rpc`.
DEFAULT_RPC: dict[int, str] = {
    1: "https://cloudflare-eth.com",
    11155111: "https://ethereum-sepolia-rpc.publicnode.com",
}


class JsonRpcError(Exception):
    pass


def _parse_ip_literal(host: str) -> IPv4Address | IPv6Address | None:
    """Parse normal and legacy numeric IP spellings without doing DNS."""
    try:
        return ip_address(host)
    except ValueError:
        try:
            return ip_address(socket.inet_ntoa(socket.inet_aton(host)))
        except OSError:
            return None


def _is_public_ip(address: IPv4Address | IPv6Address) -> bool:
    # ``ipaddress.is_global`` is also true for multicast, deprecated IPv6
    # site-local, and some reserved translation ranges. JSON-RPC endpoints
    # must be globally routable *public unicast* destinations; none of those
    # classes is a safe SSRF target.
    return (
        address.is_global
        and not address.is_multicast
        and not getattr(address, "is_site_local", False)
        and not address.is_reserved
    )


def _normalize_public_hostname(host: str) -> str:
    try:
        normalized = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise JsonRpcError("invalid_rpc_url: invalid internationalized host") from exc
    blocked_suffixes = (".localhost", ".local", ".internal", ".home.arpa")
    if (
        normalized == "localhost"
        or normalized in {"metadata", "instance-data"}
        or any(normalized.endswith(suffix) for suffix in blocked_suffixes)
        or "." not in normalized
    ):
        raise JsonRpcError("invalid_rpc_url: local or metadata host targets are not allowed")
    return normalized


def _split_rpc_url(rpc_url: str) -> SplitResult:
    """Parse the structural portion of the custom-RPC SSRF boundary."""
    if not isinstance(rpc_url, str) or not rpc_url or len(rpc_url) > 2048:
        raise JsonRpcError("invalid_rpc_url: expected a non-empty URL")
    if "\\" in rpc_url or any(ord(char) <= 0x20 or ord(char) == 0x7F for char in rpc_url):
        raise JsonRpcError("invalid_rpc_url: whitespace, control characters, and backslashes are not allowed")
    try:
        parsed = urlsplit(rpc_url)
        hostname = parsed.hostname
        # Accessing ``port`` performs urllib's malformed/out-of-range check.
        _ = parsed.port
    except ValueError as exc:
        raise JsonRpcError(f"invalid_rpc_url: {exc}") from exc
    if parsed.scheme.lower() != "https":
        raise JsonRpcError("invalid_rpc_url: RPC endpoints must use HTTPS")
    if not parsed.netloc or hostname is None:
        raise JsonRpcError("invalid_rpc_url: missing host")
    if parsed.username is not None or parsed.password is not None:
        raise JsonRpcError("invalid_rpc_url: userinfo is not allowed")
    # requests percent-decodes a hostname while preparing the request. If we
    # validated the encoded spelling, `%31%32%37.0.0.1` would look like a
    # public hostname here but connect to 127.0.0.1 later.
    if "%" in hostname:
        raise JsonRpcError("invalid_rpc_url: percent-encoded hosts are not allowed")
    return parsed


def _validate_rpc_url(rpc_url: str) -> str:
    """Validate an untrusted/custom RPC URL and return its normalized host.

    Only public HTTPS endpoint syntax is accepted here. When the request will
    connect directly, :func:`_validate_direct_dns` additionally rejects DNS
    answers in private/local/link-local ranges before any HTTP request.
    """
    parsed = _split_rpc_url(rpc_url)
    hostname = parsed.hostname
    if hostname is None:  # guarded by _split_rpc_url; keeps narrowing explicit
        raise JsonRpcError("invalid_rpc_url: missing host")

    host = hostname.rstrip(".").lower()
    if not host:
        raise JsonRpcError("invalid_rpc_url: missing host")

    # ``inet_aton`` in the helper catches legacy IPv4 spellings that
    # ``ip_address`` rejects, such as 2130706433 and 0x7f000001.
    parsed_ip = _parse_ip_literal(host)
    if parsed_ip is not None:
        if not _is_public_ip(parsed_ip):
            raise JsonRpcError("invalid_rpc_url: non-public IP targets are not allowed")
        return host

    return _normalize_public_hostname(host)


def _rpc_endpoint_display(rpc_url: str) -> str:
    """Return a credential-free origin suitable for the approval prompt."""
    parsed = _split_rpc_url(rpc_url)
    hostname = _validate_rpc_url(rpc_url)
    display_host = f"[{hostname}]" if ":" in hostname else hostname
    return f"https://{display_host}{f':{parsed.port}' if parsed.port is not None else ''}"


def _validate_direct_dns(host: str, port: int = 443) -> tuple[str, ...]:
    """Return validated public addresses for a pinned direct connection."""
    literal = _parse_ip_literal(host)
    if literal is not None:
        if not _is_public_ip(literal):
            raise JsonRpcError("invalid_rpc_url: non-public IP targets are not allowed")
        return (str(literal),)
    try:
        answers = {
            ip_address(sockaddr[0])
            for _family, _socktype, _proto, _canonname, sockaddr in socket.getaddrinfo(
                host,
                port,
                type=socket.SOCK_STREAM,
            )
        }
    except (OSError, ValueError) as exc:
        raise JsonRpcError("invalid_rpc_url: RPC host DNS resolution failed") from exc
    if not answers or any(not _is_public_ip(address) for address in answers):
        raise JsonRpcError("invalid_rpc_url: RPC host resolved to a non-public address")
    return tuple(sorted(str(address) for address in answers))


def _tor_route_active() -> bool:
    """Whether the process-wide network runtime currently promises Tor."""
    try:
        from ..network import api as network_api

        return network_api.status().active_path == "tor"
    except Exception:
        # The extension remains usable without mordred_network. A resolver
        # failure is handled separately and always fails closed.
        return False


def _resolve_route(rpc_url: str) -> tuple[dict[str, str] | None, str | None]:
    """Resolve the explicit RPC route without silently changing egress.

    A successful gateway result of ``None`` is an intentional direct route
    for clearnet or an OS-level VPN. A resolver exception is not a routing
    decision and must stop the request. Likewise, an active Tor path must
    always yield an application proxy (NO_PROXY cannot override it).
    """
    target_host = _validate_rpc_url(rpc_url)
    try:
        from gateway.platforms.base import resolve_proxy_url

        url = resolve_proxy_url(target_hosts=target_host)
    except Exception as exc:
        raise JsonRpcError("rpc_routing_unavailable: gateway proxy resolution failed") from exc
    if not url and _tor_route_active():
        raise JsonRpcError("rpc_routing_unavailable: Tor is active but no RPC proxy was resolved")
    if not url:
        parsed = _split_rpc_url(rpc_url)
        addresses = _validate_direct_dns(target_host, parsed.port or 443)
        return None, addresses[0]
    return {"http": url, "https": url}, None


def _proxies(rpc_url: str) -> dict[str, str] | None:
    """Compatibility wrapper exposing only the resolved proxy mapping."""
    return _resolve_route(rpc_url)[0]


def _direct_https_post(
    rpc_url: str,
    payload: dict[str, Any],
    *,
    address: str,
    timeout: float,
) -> tuple[int, Any]:
    """POST to a validated IP while retaining the original TLS/Host identity."""
    import urllib3

    parsed = _split_rpc_url(rpc_url)
    host = _validate_rpc_url(rpc_url)
    port = parsed.port or 443
    display_host = f"[{host}]" if ":" in host else host
    authority = f"{display_host}:{port}" if parsed.port is not None else display_host
    target = parsed.path or "/"
    if parsed.query:
        target = f"{target}?{parsed.query}"

    pool = urllib3.HTTPSConnectionPool(
        address,
        port,
        assert_hostname=host,
        server_hostname=host,
        ssl_context=ssl.create_default_context(),
    )
    try:
        response = pool.urlopen(
            "POST",
            target,
            body=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            headers={"Content-Type": "application/json", "Host": authority},
            redirect=False,
            retries=False,
            timeout=timeout,
        )
        if response.status < 200 or response.status >= 300:
            return response.status, None
        try:
            data = json.loads(response.data)
        except (TypeError, ValueError) as exc:
            raise JsonRpcError("rpc_invalid_response: expected JSON") from exc
        return response.status, data
    except JsonRpcError:
        raise
    except Exception as exc:
        raise JsonRpcError("rpc_request_failed: direct HTTPS request failed") from exc
    finally:
        pool.close()


def _proxied_https_post(
    rpc_url: str,
    payload: dict[str, Any],
    *,
    proxies: dict[str, str],
    timeout: float,
) -> tuple[int, Any]:
    """POST through the gateway route without merging ambient proxy env."""
    import requests

    try:
        with requests.Session() as session:
            session.trust_env = False
            response = session.post(
                rpc_url,
                json=payload,
                proxies=proxies,
                timeout=timeout,
                allow_redirects=False,
            )
            if response.status_code < 200 or response.status_code >= 300:
                return response.status_code, None
            try:
                data = response.json()
            except (TypeError, ValueError) as exc:
                raise JsonRpcError("rpc_invalid_response: expected JSON") from exc
            return response.status_code, data
    except JsonRpcError:
        raise
    except Exception as exc:
        raise JsonRpcError("rpc_request_failed: proxied HTTPS request failed") from exc


def call(rpc_url: str, method: str, params: list[Any], *, timeout: float = 30.0) -> Any:
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    proxies, direct_address = _resolve_route(rpc_url)
    if proxies is not None:
        status, data = _proxied_https_post(rpc_url, payload, proxies=proxies, timeout=timeout)
    elif direct_address is not None:
        status, data = _direct_https_post(rpc_url, payload, address=direct_address, timeout=timeout)
    else:  # pragma: no cover - _resolve_route guarantees one route
        raise JsonRpcError("rpc_routing_unavailable: no RPC route was resolved")

    if 300 <= status < 400:
        raise JsonRpcError("rpc_redirect_refused: RPC endpoints may not redirect")
    if status < 200 or status >= 300:
        raise JsonRpcError(f"rpc_http_error: RPC endpoint returned HTTP {status}")
    if not isinstance(data, dict):
        raise JsonRpcError("rpc_invalid_response: expected a JSON object")
    if data.get("id") != 1:
        raise JsonRpcError("rpc_invalid_response: response id mismatch")
    if data.get("error"):
        raise JsonRpcError(str(data["error"]))
    return data.get("result")


def _to_int(hexstr: Any) -> int:
    if hexstr is None:
        return 0
    if isinstance(hexstr, int):
        return hexstr
    s = str(hexstr)
    return int(s, 16) if s.startswith("0x") else int(s)


# --------------------------------------------------------------------------- #
# Field filling
# --------------------------------------------------------------------------- #


def get_nonce(rpc_url: str, address: str) -> int:
    return _to_int(call(rpc_url, "eth_getTransactionCount", [address, "pending"]))


def estimate_gas(rpc_url: str, tx: dict[str, Any], from_address: str) -> int:
    call_obj = {"from": from_address}
    for k in ("to", "value", "data"):
        if tx.get(k) not in (None, ""):
            call_obj[k] = tx[k]
    gas = _to_int(call(rpc_url, "eth_estimateGas", [call_obj]))
    return gas + gas // 5  # +20% headroom


def fee_data(rpc_url: str) -> dict[str, int]:
    """Return EIP-1559 fees from the latest block + priority fee suggestion."""
    block = call(rpc_url, "eth_getBlockByNumber", ["latest", False]) or {}
    base = _to_int(block.get("baseFeePerGas"))
    try:
        tip = _to_int(call(rpc_url, "eth_maxPriorityFeePerGas", []))
    except Exception:
        tip = 1_500_000_000  # 1.5 gwei
    if base:
        return {"maxPriorityFeePerGas": tip, "maxFeePerGas": base * 2 + tip}
    gas_price = _to_int(call(rpc_url, "eth_gasPrice", []))
    return {"gasPrice": gas_price}


def fill_transaction(rpc_url: str, tx: dict[str, Any], from_address: str, chain_id: int) -> dict[str, Any]:
    """Return a copy of ``tx`` with nonce/gas/fee fields filled where missing."""
    out = dict(tx)
    if out.get("nonce") in (None, ""):
        out["nonce"] = hex(get_nonce(rpc_url, from_address))
    has_1559 = out.get("maxFeePerGas") not in (None, "")
    has_legacy = out.get("gasPrice") not in (None, "")
    if not has_1559 and not has_legacy:
        out.update({k: hex(v) for k, v in fee_data(rpc_url).items()})
    if out.get("gas") in (None, ""):
        out["gas"] = hex(estimate_gas(rpc_url, out, from_address))
    return out


def send_raw_transaction(rpc_url: str, raw_hex: str) -> str:
    """Broadcast and return the transaction hash."""
    return str(call(rpc_url, "eth_sendRawTransaction", [raw_hex]))
