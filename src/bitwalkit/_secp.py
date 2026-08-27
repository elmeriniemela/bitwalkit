"""Bootstrap the vendored, pure-Python ``secp256k1lab`` and re-export the bits
bitwalkit needs (``GE`` group elements and the generator ``G``).

When installed, ``secp256k1lab`` is importable directly (shipped from the git
submodule at ``vendor/secp256k1lab``). For a source checkout that has not been
installed, we add the submodule's ``src`` directory to ``sys.path`` as a
fallback so the package still works without a build step.
"""

from __future__ import annotations

import os
import sys


def _bootstrap_secp256k1lab() -> None:
    try:
        import secp256k1lab  # noqa: F401
        return
    except ImportError:
        pass
    here = os.path.dirname(os.path.abspath(__file__))
    # src/bitwalkit -> repo root -> vendor/secp256k1lab/src
    candidate = os.path.abspath(
        os.path.join(here, "..", "..", "vendor", "secp256k1lab", "src")
    )
    if os.path.isdir(os.path.join(candidate, "secp256k1lab")):
        sys.path.insert(0, candidate)


_bootstrap_secp256k1lab()

try:
    from secp256k1lab.secp256k1 import G, GE  # noqa: E402
except ImportError as exc:  # pragma: no cover - misconfigured checkout
    raise ImportError(
        "bitwalkit could not import its vendored 'secp256k1lab'. If this is a "
        "git checkout, run: git submodule update --init --recursive"
    ) from exc

__all__ = ["G", "GE"]
