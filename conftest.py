"""Make the source tree importable during tests without an install step.

``bitwalkit._secp`` already adds the vendored ``secp256k1lab`` to ``sys.path``,
so only ``src`` needs to go on the path here.
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "src"))
