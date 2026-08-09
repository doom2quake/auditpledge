"""Test fixtures. Everything here runs offline, keyless, and with no GCP."""

import os
import sys
from pathlib import Path

# The tests import `auditpledge` from the checkout, not from site-packages.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# No Firestore, no LLM, no network in any test.
os.environ.setdefault("AP_IN_MEMORY_STATE", "true")
