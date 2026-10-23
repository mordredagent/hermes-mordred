"""Shared harness for the Hermes Desktop page (``desktop/assets/desktop/plugin.js``).

The page runs only inside Hermes Desktop, so the page tests check it without
Hermes: :func:`source` and :func:`block` read the module text (a label table is
``const NAME = {...}`` closed by a ``}`` in column 0), and :func:`render_page`
runs components and button handlers in Node behind a tiny SDK/React boundary:
``Button``/``Checkbox``/``Input``/``Fragment`` are plain element names, function
components are called directly, ``useState`` keeps values by call order in the
``states`` array (reset ``cursor = 0`` before re-rendering), ``useEffect`` only
collects its callbacks in ``effects`` and ``find`` walks ``props.children``. Any
new SDK import must be added here.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from importlib import resources
from typing import Any

import pytest

PAGE = resources.files("mordred_hermes.desktop").joinpath("assets", "desktop", "plugin.js")

HARNESS = """
const notifications = []
let states = [], cursor = 0
const host = {notify: n => notifications.push(n), notifyError: e => notifications.push({error: e.message})}
const Button = 'button', Checkbox = 'checkbox', Input = 'input', Fragment = 'fragment'
const ROUTES_AREA = '', SIDEBAR_NAV_AREA = '', PALETTE_AREA = ''
const effects = []
const useCallback = f => f, useEffect = f => {effects.push(f)}
const useState = initial => {
  const index = cursor++
  if (!(index in states)) states[index] = initial
  return [states[index], value => {states[index] = value}]
}
const useRef = initial => useState({current: initial})[0]
let jsx = (type, props) => typeof type === 'function' ? type(props) : {type, props}
let jsxs = jsx
const find = (node, predicate) => {
  if (!node || typeof node !== 'object') return null
  if (predicate(node)) return node
  const children = node.props && node.props.children
  for (const child of Array.isArray(children) ? children : [children]) {
    const found = find(child, predicate)
    if (found) return found
  }
  return null
}
"""


def source() -> str:
    return PAGE.read_text(encoding="utf-8")


def block(name: str) -> str:
    match = re.search(rf"const {name} = \{{(.*?)\n\}}", source(), re.S)
    assert match, f"{name} table missing"
    return match.group(1)


def render_page(script: str) -> Any:
    """Run the page components and button handlers with a tiny SDK/React boundary."""
    if shutil.which("node") is None:
        pytest.skip("Node.js is not installed")
    page = re.sub(r"^import[\s\S]*?from '[^']+'\n", "", source(), flags=re.M)
    page = page.replace("export default {", "globalThis.plugin = {")
    result = subprocess.run(
        ["node", "--input-type=module"],
        input=HARNESS + page + "\n" + script,
        text=True,
        encoding="utf-8",
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)
