"""RPC field-filling and broadcast, with the JSON-RPC transport stubbed."""

from __future__ import annotations

import sys
import types

import pytest

import mordred_hermes.extension.wallet as extension_wallet
from mordred_hermes.extension import extension_rpc


@pytest.fixture
def fake_rpc(monkeypatch):
    sent = {}

    def fake_call(rpc_url, method, params, timeout=30.0):
        if method == "eth_getTransactionCount":
            return "0x5"
        if method == "eth_getBlockByNumber":
            return {"baseFeePerGas": hex(10_000_000_000)}  # 10 gwei base
        if method == "eth_maxPriorityFeePerGas":
            return hex(1_000_000_000)  # 1 gwei tip
        if method == "eth_estimateGas":
            return hex(21000)
        if method == "eth_sendRawTransaction":
            sent["raw"] = params[0]
            return "0xtxhash"
        raise AssertionError(f"unexpected method {method}")

    monkeypatch.setattr(extension_rpc, "call", fake_call)
    return sent


def test_fill_transaction_1559(fake_rpc):
    tx = {"to": "0x" + "11" * 20, "value": "0x0"}
    filled = extension_rpc.fill_transaction("http://rpc", tx, "0x" + "ab" * 20, 1)
    assert filled["nonce"] == "0x5"
    assert filled["maxPriorityFeePerGas"] == hex(1_000_000_000)
    # maxFee = base*2 + tip = 21 gwei
    assert filled["maxFeePerGas"] == hex(10_000_000_000 * 2 + 1_000_000_000)
    # gas estimate +20%
    assert int(filled["gas"], 16) == 21000 + 21000 // 5


def test_fill_preserves_explicit_fields(fake_rpc):
    tx = {"to": "0x0", "nonce": "0x9", "gas": "0x5208", "gasPrice": "0x3b9aca00"}
    filled = extension_rpc.fill_transaction("http://rpc", tx, "0xabc", 1)
    assert filled["nonce"] == "0x9"
    assert filled["gas"] == "0x5208"
    assert filled["gasPrice"] == "0x3b9aca00"
    assert "maxFeePerGas" not in filled  # legacy preserved, no 1559 injected


def test_send_raw(fake_rpc):
    assert extension_rpc.send_raw_transaction("http://rpc", "0xdeadbeef") == "0xtxhash"
    assert fake_rpc["raw"] == "0xdeadbeef"


# --------------------------------------------------------------------------- #
# RPC URL validation and explicit route resolution
# --------------------------------------------------------------------------- #


def _install_gateway_resolver(monkeypatch, resolver):
    gateway = types.ModuleType("gateway")
    platforms = types.ModuleType("gateway.platforms")
    base = types.ModuleType("gateway.platforms.base")
    base.resolve_proxy_url = resolver  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "gateway", gateway)
    monkeypatch.setitem(sys.modules, "gateway.platforms", platforms)
    monkeypatch.setitem(sys.modules, "gateway.platforms.base", base)


def test_proxies_resolves_for_explicit_rpc_host(monkeypatch):
    """The gateway receives the target host so NO_PROXY is evaluated."""
    seen = []

    def resolve(*, target_hosts=None):
        seen.append(target_hosts)
        return "socks5h://127.0.0.1:9050"

    _install_gateway_resolver(monkeypatch, resolve)
    proxies = extension_rpc._proxies("https://rpc.example.com/v1")
    assert proxies == {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}
    assert seen == ["rpc.example.com"]


def test_proxy_resolver_failure_does_not_fallback_to_env(monkeypatch):
    """An env fallback may differ from the gateway/Tor route, so refuse it."""

    def fail(*, target_hosts=None):
        raise RuntimeError(f"resolver unavailable for {target_hosts}")

    _install_gateway_resolver(monkeypatch, fail)
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:8118")

    with pytest.raises(extension_rpc.JsonRpcError, match="rpc_routing_unavailable"):
        extension_rpc._proxies("https://rpc.example.com")


def test_tor_route_without_proxy_fails_closed(monkeypatch):
    _install_gateway_resolver(monkeypatch, lambda *, target_hosts=None: None)
    monkeypatch.setattr(extension_rpc, "_tor_route_active", lambda: True)

    with pytest.raises(extension_rpc.JsonRpcError, match="Tor is active"):
        extension_rpc._proxies("https://rpc.example.com")


def test_successful_direct_resolution_remains_valid_for_clearnet_or_vpn(monkeypatch):
    _install_gateway_resolver(monkeypatch, lambda *, target_hosts=None: None)
    monkeypatch.setattr(extension_rpc, "_tor_route_active", lambda: False)
    monkeypatch.setattr(extension_rpc, "_validate_direct_dns", lambda host, port=443: ("93.184.216.34",))

    assert extension_rpc._proxies("https://rpc.example.com") is None


def test_call_never_posts_when_route_resolution_fails(monkeypatch):
    def fail(*, target_hosts=None):
        raise RuntimeError(f"resolver unavailable for {target_hosts}")

    _install_gateway_resolver(monkeypatch, fail)
    posted = []
    monkeypatch.setattr("requests.post", lambda *args, **kwargs: posted.append((args, kwargs)))

    with pytest.raises(extension_rpc.JsonRpcError, match="rpc_routing_unavailable"):
        extension_rpc.call("https://rpc.example.com", "eth_chainId", [])
    assert posted == []


def test_call_never_posts_when_tor_proxy_is_missing(monkeypatch):
    _install_gateway_resolver(monkeypatch, lambda *, target_hosts=None: None)
    monkeypatch.setattr(extension_rpc, "_tor_route_active", lambda: True)
    posted = []
    monkeypatch.setattr("requests.post", lambda *args, **kwargs: posted.append((args, kwargs)))

    with pytest.raises(extension_rpc.JsonRpcError, match="Tor is active"):
        extension_rpc.call("https://rpc.example.com", "eth_chainId", [])
    assert posted == []


def test_direct_route_rejects_private_dns_answer_before_post(monkeypatch):
    _install_gateway_resolver(monkeypatch, lambda *, target_hosts=None: None)
    monkeypatch.setattr(extension_rpc, "_tor_route_active", lambda: False)
    monkeypatch.setattr(
        extension_rpc.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (extension_rpc.socket.AF_INET, extension_rpc.socket.SOCK_STREAM, 6, "", ("10.0.0.8", 443))
        ],
    )
    posted = []
    monkeypatch.setattr("requests.post", lambda *args, **kwargs: posted.append((args, kwargs)))

    with pytest.raises(extension_rpc.JsonRpcError, match="resolved to a non-public address"):
        extension_rpc.call("https://rpc.example.com", "eth_chainId", [])
    assert posted == []


def test_call_refuses_redirect_and_disables_automatic_redirects(monkeypatch):
    _install_gateway_resolver(
        monkeypatch,
        lambda *, target_hosts=None: "socks5h://127.0.0.1:9050",
    )
    seen = {}

    def post(_self, *args, **kwargs):
        seen.update(kwargs)

        class _Redirect:
            status_code = 302

            @staticmethod
            def json():
                return {"jsonrpc": "2.0", "id": 1, "result": None}

        return _Redirect()

    monkeypatch.setattr("requests.Session.post", post)

    with pytest.raises(extension_rpc.JsonRpcError, match="rpc_redirect_refused"):
        extension_rpc.call("https://rpc.example.com", "eth_chainId", [])
    assert seen["allow_redirects"] is False


def test_direct_route_ignores_ambient_proxy_and_pins_validated_address(monkeypatch):
    _install_gateway_resolver(monkeypatch, lambda *, target_hosts=None: None)
    monkeypatch.setattr(extension_rpc, "_tor_route_active", lambda: False)
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:8118")
    monkeypatch.setattr(
        extension_rpc,
        "_validate_direct_dns",
        lambda host, port=443: ("93.184.216.34",),
    )
    seen = {}

    def direct_post(rpc_url, payload, *, address, timeout):
        seen.update(rpc_url=rpc_url, payload=payload, address=address, timeout=timeout)
        return 200, {"jsonrpc": "2.0", "id": 1, "result": "0x1"}

    monkeypatch.setattr(extension_rpc, "_direct_https_post", direct_post)
    monkeypatch.setattr(
        "requests.Session.post",
        lambda *args, **kwargs: pytest.fail("direct route must not use requests/env proxies"),
    )

    assert extension_rpc.call("https://rpc.example.com", "eth_chainId", []) == "0x1"
    assert seen["address"] == "93.184.216.34"


def test_direct_route_rebinding_cannot_trigger_second_dns_lookup(monkeypatch):
    _install_gateway_resolver(monkeypatch, lambda *, target_hosts=None: None)
    monkeypatch.setattr(extension_rpc, "_tor_route_active", lambda: False)
    lookups = []

    def resolve(*args, **kwargs):
        lookups.append((args, kwargs))
        if len(lookups) > 1:
            return [(extension_rpc.socket.AF_INET, extension_rpc.socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
        return [(extension_rpc.socket.AF_INET, extension_rpc.socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    monkeypatch.setattr(extension_rpc.socket, "getaddrinfo", resolve)
    seen = {}

    def direct_post(_rpc_url, _payload, *, address, timeout):
        seen["address"] = address
        return 200, {"jsonrpc": "2.0", "id": 1, "result": "0x1"}

    monkeypatch.setattr(extension_rpc, "_direct_https_post", direct_post)

    assert extension_rpc.call("https://rpc.example.com", "eth_chainId", []) == "0x1"
    assert seen["address"] == "93.184.216.34"
    assert len(lookups) == 1


def test_direct_https_post_pins_ip_but_keeps_original_host_and_tls_name(monkeypatch):
    import urllib3

    seen = {}

    class _Response:
        status = 200
        data = b'{"jsonrpc":"2.0","id":1,"result":"0x1"}'

    class _Pool:
        def __init__(self, host, port, **kwargs):
            seen.update(connect_host=host, connect_port=port, pool_kwargs=kwargs)

        def urlopen(self, method, target, **kwargs):
            seen.update(method=method, target=target, request_kwargs=kwargs)
            return _Response()

        def close(self):
            seen["closed"] = True

    monkeypatch.setattr(urllib3, "HTTPSConnectionPool", _Pool)

    status, data = extension_rpc._direct_https_post(
        "https://rpc.example.com:8443/v1/key?network=mainnet",
        {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []},
        address="93.184.216.34",
        timeout=4.0,
    )

    assert (status, data["result"]) == (200, "0x1")
    assert seen["connect_host"] == "93.184.216.34"
    assert seen["connect_port"] == 8443
    assert seen["pool_kwargs"]["server_hostname"] == "rpc.example.com"
    assert seen["pool_kwargs"]["assert_hostname"] == "rpc.example.com"
    assert seen["request_kwargs"]["headers"]["Host"] == "rpc.example.com:8443"
    assert seen["target"] == "/v1/key?network=mainnet"
    assert seen["closed"] is True


@pytest.mark.parametrize(
    "rpc_url",
    [
        "http://rpc.example.com",
        "https://user:secret@rpc.example.com",
        "https://localhost",
        "https://localhost./rpc",
        "https://127.0.0.1",
        "https://%31%32%37.0.0.1",
        "https://127%2e0%2e0%2e1",
        "https://2130706433",
        "https://10.0.0.1",
        "https://169.254.169.254/latest/meta-data",
        "https://224.0.0.1",
        "https://239.255.255.250",
        "https://[::1]",
        "https://[ff02::1]",
        "https://[ff0e::1]",
        "https://[fec0::1]",
        "https://[64:ff9b::7f00:1]",
        "https://metadata.google.internal",
        "https://instance-data",
        "https://rpc.example.com /v1",
    ],
)
def test_validate_rpc_url_rejects_non_https_or_non_public_targets(rpc_url):
    with pytest.raises(extension_rpc.JsonRpcError, match="invalid_rpc_url"):
        extension_rpc._validate_rpc_url(rpc_url)


def test_validate_rpc_url_accepts_public_custom_https_endpoint():
    assert (
        extension_rpc._validate_rpc_url("https://rpc.example.com/v1/project-key?network=mainnet") == "rpc.example.com"
    )
    assert (
        extension_rpc._rpc_endpoint_display("https://rpc.example.com:8443/v1/project-key?network=mainnet")
        == "https://rpc.example.com:8443"
    )


@pytest.mark.parametrize(
    "answer",
    [
        "224.0.0.1",
        "239.255.255.250",
        "ff02::1",
        "ff0e::1",
        "fec0::1",
        "64:ff9b::7f00:1",
    ],
)
def test_direct_route_rejects_multicast_dns_answers(monkeypatch, answer):
    family = extension_rpc.socket.AF_INET6 if ":" in answer else extension_rpc.socket.AF_INET
    sockaddr = (answer, 443, 0, 0) if family == extension_rpc.socket.AF_INET6 else (answer, 443)
    monkeypatch.setattr(
        extension_rpc.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(family, extension_rpc.socket.SOCK_STREAM, 6, "", sockaddr)],
    )

    with pytest.raises(extension_rpc.JsonRpcError, match="resolved to a non-public address"):
        extension_rpc._validate_direct_dns("rpc.example.com")


def test_prepare_sign_freezes_chain_rpc_and_filled_transaction(monkeypatch):
    from mordred_hermes.keyvault import extension_sign

    monkeypatch.setattr(extension_sign, "get_address", lambda: "0x" + "aa" * 20)
    monkeypatch.setattr(extension_sign, "rpc_url_for", lambda chain_id: "https://rpc.example.com/private-key")
    monkeypatch.setattr(
        extension_rpc,
        "fill_transaction",
        lambda rpc_url, tx, from_address, chain_id: {
            **tx,
            "nonce": "0x1",
            "gas": "0x5208",
            "gasPrice": "0x3b9aca00",
        },
    )

    prepared = extension_wallet._prepare_sign(
        "eth_sendTransaction",
        [{"from": ("0x" + "aa" * 20).upper(), "to": "0x" + "11" * 20, "value": "0x1"}],
        "0x1",
    )

    assert prepared.params == [
        {
            "type": "0x0",
            "chainId": "0x1",
            "nonce": "0x1",
            "gasPrice": "0x3b9aca00",
            "gas": "0x5208",
            "to": "0x" + "11" * 20,
            "value": "0x1",
            "data": "0x",
            "from": "0x" + "aa" * 20,
        }
    ]
    assert prepared.chain_id == "0x1"
    assert prepared.rpc_url == "https://rpc.example.com/private-key"
    assert prepared.rpc_endpoint == "https://rpc.example.com"
    assert prepared.expected_signer == "0x" + "aa" * 20


def test_prepare_sign_rejects_transaction_from_other_wallet(monkeypatch):
    from mordred_hermes.keyvault import extension_sign

    signer = "0x" + "aa" * 20
    monkeypatch.setattr(extension_sign, "chain_id_int", lambda: 1)
    monkeypatch.setattr(extension_sign, "rpc_url_for", lambda _chain_id: None)
    monkeypatch.setattr(extension_sign, "get_address", lambda: signer)

    with pytest.raises(ValueError, match="transaction_from_mismatch"):
        extension_wallet._prepare_sign(
            "eth_sendTransaction",
            [{"from": "0x" + "bb" * 20, "to": "0x" + "11" * 20}],
            "0x1",
        )


@pytest.mark.parametrize(
    ("transaction", "error"),
    [
        (
            {
                "type": "0x1",
                "nonce": "0x0",
                "gasPrice": "0x1",
                "gas": "0x5208",
                "to": "0x" + "11" * 20,
            },
            "unsupported_transaction_type",
        ),
        (
            {
                "type": "0x3",
                "nonce": "0x0",
                "maxPriorityFeePerGas": "0x1",
                "maxFeePerGas": "0x2",
                "gas": "0x5208",
                "to": "0x" + "11" * 20,
            },
            "unsupported_transaction_type",
        ),
        (
            {
                "type": "0x2",
                "nonce": "0x0",
                "maxPriorityFeePerGas": "0x1",
                "maxFeePerGas": "0x2",
                "gas": "0x5208",
                "to": "0x" + "11" * 20,
                "accessList": [{"address": "0x" + "22" * 20, "storageKeys": []}],
            },
            "unsupported_transaction_access_list",
        ),
        (
            {
                "nonce": -1,
                "gasPrice": "0x1",
                "gas": "0x5208",
                "to": "0x" + "11" * 20,
            },
            "invalid_transaction_quantity:nonce",
        ),
    ],
)
def test_prepare_sign_rejects_transactions_the_serializer_cannot_match(monkeypatch, transaction, error):
    from mordred_hermes.keyvault import extension_sign

    signer = "0x" + "aa" * 20
    monkeypatch.setattr(extension_sign, "chain_id_int", lambda: 1)
    monkeypatch.setattr(extension_sign, "rpc_url_for", lambda _chain_id: None)
    monkeypatch.setattr(extension_sign, "get_address", lambda: signer)

    with pytest.raises(ValueError, match=error):
        extension_wallet._prepare_sign("eth_sendTransaction", [transaction], "0x1")


@pytest.mark.parametrize(
    ("method", "params"),
    [
        ("personal_sign", ["0xdeadbeef", "0x" + "bb" * 20]),
        ("eth_signTypedData_v4", ["0x" + "bb" * 20, {"types": {}, "message": {}}]),
    ],
)
def test_prepare_sign_rejects_requested_account_for_message_methods(monkeypatch, method, params):
    from mordred_hermes.keyvault import extension_sign

    monkeypatch.setattr(extension_sign, "get_address", lambda: "0x" + "aa" * 20)

    with pytest.raises(ValueError, match=rf"{method}_account_mismatch"):
        extension_wallet._prepare_sign(method, params)


@pytest.mark.parametrize(
    ("method", "params", "error"),
    [
        ("personal_sign", ["0xdeadbeef"], "invalid_personal_sign_params"),
        ("personal_sign", ["0xdeadbeef", {"account": "not-a-string"}], "invalid_personal_sign_params"),
        (
            "eth_signTypedData_v4",
            [{"types": {}, "message": {}}, "0x" + "aa" * 20],
            "invalid_eth_signTypedData_v4_params",
        ),
        ("eth_signTypedData_v4", ["0x" + "aa" * 20], "invalid_eth_signTypedData_v4_params"),
    ],
)
def test_prepare_sign_strictly_validates_message_param_shapes(method, params, error):
    with pytest.raises(ValueError, match=error):
        extension_wallet._prepare_sign(method, params)


@pytest.mark.parametrize(
    ("method", "params"),
    [
        ("personal_sign", ["0xdeadbeef", "0x" + "aa" * 20]),
        ("eth_signTypedData_v4", ["0x" + "aa" * 20, {"types": {}, "message": {}}]),
    ],
)
def test_message_sign_rejects_signature_from_wallet_changed_after_precheck(monkeypatch, method, params):
    from mordred_hermes.keyvault import extension_sign

    expected_signer = "0x" + "aa" * 20
    actual_signer = "0x" + "bb" * 20
    monkeypatch.setattr(extension_sign, "get_address", lambda: expected_signer)
    monkeypatch.setattr(extension_sign, "personal_sign", lambda _payload: "0xsigned-by-b")
    monkeypatch.setattr(extension_sign, "sign_typed_data_v4", lambda _payload: "0xsigned-by-b")
    monkeypatch.setattr(extension_wallet, "_recover_personal_signer", lambda _payload, _signature: actual_signer)
    monkeypatch.setattr(extension_wallet, "_recover_typed_data_signer", lambda _payload, _signature: actual_signer)

    with pytest.raises(RuntimeError, match="wallet_signer_changed"):
        extension_wallet._do_sign(method, params, expected_signer=expected_signer)


def test_send_prepared_transaction_never_refills_and_checks_broadcast_hash(monkeypatch):
    from mordred_hermes.keyvault import extension_sign

    signer = "0x" + "aa" * 20
    tx = {
        "type": "0x0",
        "chainId": "0x1",
        "nonce": "0x1",
        "gasPrice": "0x3b9aca00",
        "gas": "0x5208",
        "to": "0x" + "11" * 20,
        "value": "0x0",
        "data": "0x",
        "from": signer,
    }
    seen = {}

    def sign_transaction(candidate, *, chain_id):
        seen["tx"] = candidate
        seen["chain_id"] = chain_id
        return {"raw": "0xraw", "hash": "0xabc"}

    monkeypatch.setattr(extension_sign, "get_address", lambda: signer.upper())
    monkeypatch.setattr(extension_sign, "sign_transaction", sign_transaction)
    monkeypatch.setattr(extension_wallet, "_recover_transaction_signer", lambda _raw: signer.upper())
    monkeypatch.setattr(extension_rpc, "fill_transaction", lambda *args, **kwargs: pytest.fail("must not refill"))
    monkeypatch.setattr(extension_rpc, "send_raw_transaction", lambda rpc_url, raw: "0xAbC")

    assert (
        extension_wallet._send_prepared_transaction(
            tx,
            "0x1",
            "https://rpc.example.com",
            expected_signer=signer,
        )
        == "0xAbC"
    )
    assert seen == {"tx": tx, "chain_id": 1}

    monkeypatch.setattr(extension_rpc, "send_raw_transaction", lambda rpc_url, raw: "0xdef")
    with pytest.raises(RuntimeError, match="mismatched transaction hash"):
        extension_wallet._send_prepared_transaction(
            tx,
            "0x1",
            "https://rpc.example.com",
            expected_signer=signer,
        )


def test_transaction_sign_rejects_raw_tx_from_wallet_changed_after_precheck(monkeypatch):
    from mordred_hermes.keyvault import extension_sign

    expected_signer = "0x" + "aa" * 20
    actual_signer = "0x" + "bb" * 20
    tx = {
        "type": "0x0",
        "chainId": "0x1",
        "nonce": "0x1",
        "gasPrice": "0x3b9aca00",
        "gas": "0x5208",
        "to": "0x" + "11" * 20,
        "value": "0x0",
        "data": "0x",
        "from": expected_signer,
    }
    monkeypatch.setattr(extension_sign, "get_address", lambda: expected_signer)
    monkeypatch.setattr(
        extension_sign,
        "sign_transaction",
        lambda _tx, *, chain_id: {"raw": "0xsigned-by-b", "hash": "0xhash"},
    )
    monkeypatch.setattr(extension_wallet, "_recover_transaction_signer", lambda _raw: actual_signer)
    monkeypatch.setattr(
        extension_rpc,
        "send_raw_transaction",
        lambda *_args, **_kwargs: pytest.fail("mismatched signer must be rejected before broadcast"),
    )

    with pytest.raises(RuntimeError, match="wallet_signer_changed"):
        extension_wallet._send_prepared_transaction(
            tx,
            "0x1",
            "https://rpc.example.com",
            expected_signer=expected_signer,
        )


def test_prepare_sign_rejects_transaction_chain_mismatch():
    with pytest.raises(ValueError, match="transaction_chain_id_mismatch"):
        extension_wallet._prepare_sign(
            "eth_sendTransaction",
            [{"chainId": "0x5", "to": "0x" + "11" * 20}],
            "0x1",
            "https://rpc.example.com",
        )


def test_prepare_sign_rejects_request_rpc_not_selected_by_operator(monkeypatch):
    from mordred_hermes.keyvault import extension_sign

    monkeypatch.setattr(extension_sign, "chain_id_int", lambda: 1)
    monkeypatch.setattr(extension_sign, "rpc_url_for", lambda _chain_id: "https://trusted.example/rpc")
    monkeypatch.setattr(
        extension_sign,
        "get_address",
        lambda: pytest.fail("must reject before disclosing the address"),
    )

    with pytest.raises(ValueError, match="rpc_endpoint_not_allowed"):
        extension_wallet._prepare_sign(
            "eth_sendTransaction",
            [{"to": "0x" + "11" * 20}],
            "0x1",
            "https://attacker.example/rpc",
        )


def test_prepare_sign_rejects_chain_not_selected_by_operator(monkeypatch):
    from mordred_hermes.keyvault import extension_sign

    monkeypatch.setattr(extension_sign, "chain_id_int", lambda: 1)

    with pytest.raises(ValueError, match="transaction_chain_id_not_allowed"):
        extension_wallet._prepare_sign(
            "eth_sendTransaction",
            [{"to": "0x" + "11" * 20}],
            "0xaa36a7",
        )
