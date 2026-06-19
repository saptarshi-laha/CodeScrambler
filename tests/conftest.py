"""Shared test fixtures.

Adds the repository root to ``sys.path`` so ``import codescrambler`` and
``import pe_builder`` both work when pytest is run from anywhere.
"""

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

_TESTS = os.path.dirname(os.path.abspath(__file__))
if _TESTS not in sys.path:
    sys.path.insert(0, _TESTS)
