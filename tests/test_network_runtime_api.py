"""Network runtime public API lifecycle."""

from __future__ import annotations

from tests._network_runtime_fakes import _make_runtime


class TestApiIntegration:
    def test_runtime_implements_api_protocol(self) -> None:
        from mordred_hermes.network import api

        rt = _make_runtime()
        api.set_runtime(rt)
        try:
            api.use("tor")
            s = api.status()
            assert s.active_path == "tor"
            assert s.ready is True
            assert s.last_health is True
            assert api.health() is True

            api.use("clearnet")
            clearnet = api.status()
            assert clearnet.active_path == "clearnet"
            assert clearnet.ready is True
        finally:
            rt.stop()
            api.reset_runtime_for_tests()
