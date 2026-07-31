"""Regression: _derive_device_name must strip the '.local' suffix as a
SUFFIX, not as a character set.

The original used `n.rstrip(".local")`, which reads that string as a set
of characters {'.', 'l', 'o', 'c', 'a'} and strips any trailing run of
them - so `Anna.local` became `Ann` and any device whose mDNS name ended
in one of those characters got silently truncated. The dashboard's
Devices and Browsing views showed the mangled names.

We extract the function via AST so importing the module (which starts the
Dash app at import time) is not required.
"""
import ast
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _extract_derive_device_name():
    src = open(os.path.join(REPO, "app", "dashboard_module.py")).read()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and \
                node.name == "_derive_device_name":
            ns = {}
            exec(ast.unparse(node), ns)
            return ns["_derive_device_name"]
    raise RuntimeError("_derive_device_name not found in dashboard_module.py")


def test_derive_device_name_strips_dot_local_as_suffix_not_charset():
    f = _extract_derive_device_name()
    # The literal bug case - names ending in .local, and specifically the
    # ones whose *last* character before the dot is in {l,o,c,a} would be
    # over-stripped.
    assert f("192.168.1.10", ["Anna.local"], "Model") == "Anna"
    assert f("192.168.1.10", ["MacBook.local"], "Model") == "MacBook"
    assert f("192.168.1.10", ["router.local"], "Model") == "router"
    # Trailing dot on the mDNS name (common in wire format)
    assert f("192.168.1.10", ["host.local."], "Model") == "host"
    # Names without .local pass through
    assert f("192.168.1.10", ["printer"], "Model") == "printer"
    # Service-record prefixes still skipped, model-plus-octet fallback used
    assert f("192.168.1.10", ["_ipp._tcp"], "Generic") == "Generic-10"
