# The verdict logic of verify_hostname_check.py, on every combination the fake venues can report.
# Runs without quickfix: the module is loaded with a stub so judge() is importable on a machine
# that has no engine at all.
import importlib.util
import sys
import types
from pathlib import Path

import pytest

SCRIPT_PATH = Path(__file__).with_name("verify_hostname_check.py")


def _load_script():
    if "quickfix" not in sys.modules:
        stub = types.ModuleType("quickfix")
        stub.Application = object
        sys.modules["quickfix"] = stub
    spec = importlib.util.spec_from_file_location("verify_hostname_check", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


script = _load_script()
COMPLETED_WITH_LOGON = ("completed", 86)
REFUSED = ("refused (SSLV3_ALERT_BAD_CERTIFICATE)", 0)


def test_judge_reports_present_when_only_the_mismatched_leaf_is_refused():
    present, reason = script.judge(COMPLETED_WITH_LOGON, REFUSED)

    assert present
    assert "refused" in reason


def test_judge_reports_absent_when_the_mismatched_leaf_completes_and_receives_the_logon():
    present, reason = script.judge(COMPLETED_WITH_LOGON, COMPLETED_WITH_LOGON)

    assert not present
    assert "Logon was sent" in reason


@pytest.mark.parametrize("matching", [REFUSED, ("no connection", 0), ("completed", 0)],
                         ids=["refused", "never-connected", "completed-but-silent"])
def test_judge_reports_absent_when_the_positive_control_fails(matching):
    # An engine that refuses everything, or never connects, must not pass as "checks the name".
    present, reason = script.judge(matching, REFUSED)

    assert not present
    assert "matching" in reason
