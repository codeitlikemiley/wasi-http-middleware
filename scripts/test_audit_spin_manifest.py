#!/usr/bin/env python3
"""Negative and positive contract tests for the Spin manifest auditor."""

from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("audit-spin-manifest.py")
SPEC = importlib.util.spec_from_file_location("audit_spin_manifest", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Spin manifest auditor")
AUDITOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDITOR)


def manifest(*, stack: bool = True, hosts: str | None = None, policy: str | None = None) -> str:
    middleware = """
dependencies.middleware = [
  { component = "request-id" },
  { component = "security-headers" },
  { component = "cors", inherit_configuration = ["environment"] },
  { component = "auth-policy", inherit_configuration = ["environment", "allowed_outbound_hosts"] },
]
""" if stack else ""
    host_list = hosts or '["https://policy.example"]'
    policy_url = policy or "https://policy.example/check"
    return f"""
spin_manifest_version = 2

[[trigger.http]]
route = "/..."
component = "app"
{middleware}
[component.app]
source = "app.wasm"
allowed_outbound_hosts = {host_list}

[component.app.environment]
WASI_MIDDLEWARE_POLICY_URL = "{policy_url}"

[component.request-id]
source = "request-id.wasm"
[component.security-headers]
source = "security-headers.wasm"
[component.cors]
source = "cors.wasm"
[component.auth-policy]
source = "auth-policy.wasm"
"""


class AuditTests(unittest.TestCase):
    """Exercise the deployment trust-boundary invariants."""

    def audit(self, contents: str) -> list[str]:
        with tempfile.NamedTemporaryFile("w", suffix=".toml") as fixture:
            fixture.write(contents)
            fixture.flush()
            return AUDITOR.audit(pathlib.Path(fixture.name), [])

    def test_accepts_exact_chain_and_policy_host(self) -> None:
        self.assertEqual(self.audit(manifest()), [])

    def test_rejects_unwrapped_application(self) -> None:
        self.assertTrue(self.audit(manifest(stack=False)))

    def test_rejects_broad_auth_network_inheritance(self) -> None:
        errors = self.audit(
            manifest(hosts='["https://policy.example", "https://other.example"]')
        )
        self.assertTrue(any("only policy host" in error for error in errors))

    def test_rejects_policy_url_host_mismatch(self) -> None:
        errors = self.audit(manifest(policy="https://other.example/check"))
        self.assertTrue(any("only policy host" in error for error in errors))

    def test_rejects_missing_middleware_source(self) -> None:
        errors = self.audit(manifest().replace('source = "cors.wasm"', ""))
        self.assertTrue(any("has no source" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
