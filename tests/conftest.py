"""Pytest bootstrap for the ARP spoofer test suite.

This runs *before* any test module is imported. It does two things:

1. Puts the repository root on ``sys.path`` so ``import arp_spoofer`` works.
2. Replaces Scapy with a ``MagicMock`` in ``sys.modules`` *before* arp_spoofer
   is imported. This guarantees the real Scapy is never touched and that no
   ARP packet can ever leave the machine while the tests run.
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

# 1. Make the module under test importable.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# 2. Stub Scapy so `import scapy.all as scapy` binds to a harmless mock.
#    Using the same mock object for both names mirrors how the import binds.
_SCAPY_STUB = MagicMock(name="scapy_stub")
sys.modules.setdefault("scapy", _SCAPY_STUB)
sys.modules.setdefault("scapy.all", _SCAPY_STUB)
