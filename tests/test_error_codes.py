"""Error-code extraction and decoding."""

from __future__ import annotations

import pytest

from src.error_codes import decode_any, decode_exit_code, decode_hresult, extract_codes


def test_win32_hresults_are_unwrapped():
    code = decode_hresult(0x80070643)
    assert code.name == "HRESULT_FROM_WIN32(ERROR_INSTALL_FAILURE)"
    assert "msiLogs" in code.hint


@pytest.mark.parametrize(
    ("value", "name"),
    [
        (0x80240017, "WU_E_NOT_APPLICABLE"),
        (0x800F0922, "CBS_E_INSTALLERS_FAILED"),
        (0x80004005, "E_FAIL"),
        (0x80070BC2, "HRESULT_FROM_WIN32(ERROR_SUCCESS_REBOOT_REQUIRED)"),
    ],
)
def test_known_hresults(value, name):
    assert decode_hresult(value).name == name


def test_unknown_windows_update_code_still_gets_a_family():
    assert decode_hresult(0x8024FFFE).name == "WU_E_*"


def test_success_exit_codes():
    assert decode_exit_code(3010).is_success
    assert decode_exit_code(1641).is_success
    assert not decode_exit_code(1603).is_success


def test_extract_finds_each_code_family_once():
    text = (
        "Installation of patch failed with exit code [1603]; retry got result code 0x800F0922 and again 0x800F0922; "
        "helper returned -2147467259; Tenable status code 401; Operations Manager http status [500]."
    )
    found = {code.display(): code.kind for code in extract_codes(text)}
    assert found == {
        "1603": "exit_code",
        "0x800F0922": "hresult",
        "0x80004005": "hresult",
        "401": "http_status",
        "500": "http_status",
    }


def test_adaptiva_internal_codes_are_not_decoded_as_windows_errors():
    codes = extract_codes("Error Message = Could not complete REST API call., Error Code = 1 (0x1), Source Object = null")
    assert [(c.kind, c.value) for c in codes] == [("adaptiva", 1)]
    assert codes[0].name is None


def test_msi_markers():
    codes = extract_codes(
        "Action ended 10:01:02: InstallFinalize. Return value 3.\n"
        "Installation success or error status: 1603.\n"
        "CustomAction CA_X returned actual error code 1603 (note this may not be 100% accurate)"
    )
    kinds = {(c.kind, c.value) for c in codes}
    assert ("msi_action_result", 3) in kinds
    assert ("exit_code", 1603) in kinds


@pytest.mark.parametrize(
    ("text", "kind", "value"),
    [
        ("0x80070643", "hresult", 0x80070643),
        ("-2147467259", "hresult", 0x80004005),
        ("1603", "exit_code", 1603),
        ("http 407", "http_status", 407),
        ("0x5", "exit_code", 5),
    ],
)
def test_decode_any(text, kind, value):
    code = decode_any(text)
    assert code is not None and code.kind == kind and code.value == value


def test_decode_any_rejects_non_codes():
    assert decode_any("abc") is None
    assert decode_any("") is None
