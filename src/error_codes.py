"""Find and decode the numeric error codes that turn up in patching logs.

Covers Windows Installer / Win32 exit codes, HRESULTs (FACILITY_WIN32 codes are
unwrapped to their Win32 value), Windows Update Agent (0x8024xxxx) and component
servicing (0x800Fxxxx) codes, WinHTTP/WinINet transport codes and HTTP statuses.

Adaptiva's own ``Error Code = N (0xN)`` values are extracted but never decoded as
Windows errors: they are internal to the product and mean something else.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

#: Exit codes that mean the install worked (possibly needing a restart).
SUCCESS_CODES = frozenset({0, 1641, 3010})

# code -> (symbolic name, meaning, hint)
WIN32_CODES: dict[int, tuple[str, str, str]] = {
    0: ("ERROR_SUCCESS", "The operation completed successfully.", "Not a failure."),
    1: ("ERROR_INVALID_FUNCTION", "Incorrect function.", "Often a generic failure from a script or custom installer."),
    2: ("ERROR_FILE_NOT_FOUND", "The system cannot find the file specified.", "Check that the content downloaded completely and the installer path exists."),
    3: ("ERROR_PATH_NOT_FOUND", "The system cannot find the path specified.", "Check that the content downloaded completely and the installer path exists."),
    5: ("ERROR_ACCESS_DENIED", "Access is denied.", "Security software, file locks or permissions on the install location."),
    14: ("ERROR_OUTOFMEMORY", "Not enough memory resources are available to complete this operation.", "Check memory pressure on the device."),
    32: ("ERROR_SHARING_VIOLATION", "The file is being used by another process.", "The application being patched was running; close it or patch during a maintenance window."),
    87: ("ERROR_INVALID_PARAMETER", "The parameter is incorrect.", "Check the install command line."),
    112: ("ERROR_DISK_FULL", "There is not enough space on the disk.", "Free disk space on the device."),
    1058: ("ERROR_SERVICE_DISABLED", "The service cannot be started because it is disabled.", "For Windows Update codes this usually means wuauserv or BITS is disabled."),
    1460: ("ERROR_TIMEOUT", "This operation returned because the timeout period expired.", "The installer hung or ran past its timeout."),
    1601: ("ERROR_INSTALL_SERVICE_FAILURE", "The Windows Installer service could not be accessed.", "Check the msiserver service on the device."),
    1602: ("ERROR_INSTALL_USEREXIT", "User cancelled installation.", "A user or an interactive prompt cancelled the install."),
    1603: ("ERROR_INSTALL_FAILURE", "Fatal error during installation.", "Generic MSI failure: open the product's log in msiLogs and read the lines just above 'Return value 3'."),
    1605: ("ERROR_UNKNOWN_PRODUCT", "This action is only valid for products that are currently installed.", "The product was not installed (already removed, or a different product code)."),
    1612: ("ERROR_INSTALL_SOURCE_ABSENT", "The installation source for this product is not available.", "The original MSI source is gone; the patch cannot find the cached package."),
    1614: ("ERROR_PRODUCT_UNINSTALLED", "The product is uninstalled.", "The product is no longer installed on the device."),
    1618: ("ERROR_INSTALL_ALREADY_RUNNING", "Another installation is already in progress.", "Another msiexec or Windows Update install was running; retry later."),
    1619: ("ERROR_INSTALL_PACKAGE_OPEN_FAILED", "This installation package could not be opened.", "Check the downloaded package is complete and not blocked."),
    1620: ("ERROR_INSTALL_PACKAGE_INVALID", "This installation package could not be opened. It may not be a valid Windows Installer package.", "Corrupt or wrong package."),
    1624: ("ERROR_INSTALL_TRANSFORM_FAILURE", "Error applying transforms.", "A transform (.mst) is missing or does not match the package."),
    1625: ("ERROR_INSTALL_PACKAGE_REJECTED", "This installation is forbidden by system policy.", "A Group Policy or AppLocker rule blocked the install."),
    1632: ("ERROR_INSTALL_TEMP_UNWRITABLE", "The Temp folder is on a drive that is full or is inaccessible.", "Check free space and permissions on the temp folder."),
    1633: ("ERROR_INSTALL_PLATFORM_UNSUPPORTED", "This installation package is not supported by this processor type.", "Wrong architecture (x86/x64/ARM64) for this device."),
    1638: ("ERROR_PRODUCT_VERSION", "Another version of this product is already installed.", "Uninstall the other version or use the upgrade package."),
    1639: ("ERROR_INVALID_COMMAND_LINE", "Invalid command line argument.", "Check the install command line."),
    1641: ("ERROR_SUCCESS_REBOOT_INITIATED", "The installer has initiated a restart.", "Success; the installer restarted the device."),
    1642: ("ERROR_PATCH_TARGET_NOT_FOUND", "The upgrade cannot be installed because the program to be upgraded may be missing, or the upgrade may update a different version of the program.", "The patch does not apply to the installed version."),
    3010: ("ERROR_SUCCESS_REBOOT_REQUIRED", "A restart is required to complete the install.", "Success; a restart is still pending."),
    3017: ("ERROR_FAIL_REBOOT_REQUIRED", "The requested operation failed. A system reboot is required to roll back changes made.", "Restart the device and retry."),
    12002: ("ERROR_WINHTTP_TIMEOUT", "The request has timed out.", "Network path to the download or update source timed out."),
    12007: ("ERROR_WINHTTP_NAME_NOT_RESOLVED", "The server name could not be resolved.", "DNS resolution failed for the download or update source."),
    12029: ("ERROR_WINHTTP_CANNOT_CONNECT", "The attempt to connect to the server failed.", "Firewall or proxy is blocking the connection."),
    12030: ("ERROR_WINHTTP_CONNECTION_ERROR", "The connection with the server was reset or terminated.", "Proxy, TLS inspection or an unstable network path."),
    12175: ("ERROR_WINHTTP_SECURE_FAILURE", "A TLS/SSL error occurred (certificate or protocol negotiation).", "Check the device clock, TLS inspection proxies and trusted root certificates."),
    14098: ("ERROR_SXS_COMPONENT_STORE_CORRUPT", "The component store has been corrupted.", "Repair Windows servicing (DISM /Online /Cleanup-Image /RestoreHealth)."),
}

# full 32-bit HRESULT -> (name, meaning, hint)
HRESULT_CODES: dict[int, tuple[str, str, str]] = {
    0x80004004: ("E_ABORT", "Operation aborted.", "The operation was cancelled."),
    0x80004005: ("E_FAIL", "Unspecified error.", "Generic failure; the surrounding log lines carry the real reason."),
    0x8000FFFF: ("E_UNEXPECTED", "Catastrophic failure.", "Unexpected internal failure; retry and check the surrounding lines."),
    0x80240009: ("WU_E_OPERATIONINPROGRESS", "Another conflicting operation was in progress.", "Another Windows Update operation was running; retry later."),
    0x8024000B: ("WU_E_CALL_CANCELLED", "Operation was cancelled.", "The update operation was cancelled."),
    0x80240016: ("WU_E_INSTALL_NOT_ALLOWED", "Operation tried to install while another installation was in progress or the system was pending a mandatory restart.", "Restart the device and retry."),
    0x80240017: ("WU_E_NOT_APPLICABLE", "Operation was not performed because there are no applicable updates.", "The update does not apply (already installed, superseded, or wrong edition)."),
    0x8024001E: ("WU_E_SERVICE_STOP", "Operation did not complete because the service or system was being shut down.", "The device restarted or shut down during the operation."),
    0x80240020: ("WU_E_NO_INTERACTIVE_USER", "Operation did not complete because there is no logged-on interactive user.", "The update needs a logged-on user."),
    0x80240022: ("WU_E_ALL_UPDATES_FAILED", "Operation failed for all the updates.", "Look for the per-update error codes nearby."),
    0x8024002E: ("WU_E_WU_DISABLED", "Access to an unmanaged server is not allowed.", "Policy blocks access to Microsoft Update; check WSUS/Windows Update policies."),
    0x80240FFF: ("WU_E_UNEXPECTED", "An operation failed due to reasons not covered by another error code.", "Generic Windows Update failure."),
    0x80242006: ("WU_E_UH_INVALIDMETADATA", "A handler operation could not be completed because the update contains invalid metadata.", "Re-download the update content."),
    0x8024200D: ("WU_E_UH_NEEDANOTHERDOWNLOAD", "The update handler did not install the update because it needs to be downloaded again.", "Re-download the update content."),
    0x80242016: ("WU_E_UH_POSTREBOOTUNEXPECTEDSTATE", "The state of the update after its post-reboot operation has completed is unexpected.", "Check the device's update history after the restart."),
    0x80244007: ("WU_E_PT_SOAPCLIENT_SOAPFAULT", "SOAP client failed because there was a SOAP fault.", "The update server returned a fault."),
    0x80244010: ("WU_E_PT_EXCEEDED_MAX_SERVER_TRIPS", "The number of round trips to the server exceeded the maximum limit.", "Retry the scan."),
    0x80244017: ("WU_E_PT_HTTP_STATUS_DENIED", "HTTP 401: access denied.", "Proxy or update source authentication failed."),
    0x80244018: ("WU_E_PT_HTTP_STATUS_FORBIDDEN", "HTTP 403: forbidden.", "Proxy or update source refused the request."),
    0x80244019: ("WU_E_PT_HTTP_STATUS_NOT_FOUND", "HTTP 404: not found.", "The update file is not available at the source."),
    0x8024401B: ("WU_E_PT_HTTP_STATUS_PROXY_AUTH_REQ", "HTTP 407: proxy authentication required.", "Configure proxy authentication for the SYSTEM account."),
    0x80244022: ("WU_E_PT_HTTP_STATUS_SERVICE_UNAVAIL", "HTTP 503: service unavailable.", "The update source was temporarily unavailable; retry."),
    0x8024402C: ("WU_E_PT_WINHTTP_NAME_NOT_RESOLVED", "The proxy server or target server name cannot be resolved.", "Check DNS and proxy settings on the device."),
    0x80246007: ("WU_E_DM_NOTDOWNLOADED", "The update has not been downloaded.", "Content download did not finish."),
    0x80246008: ("WU_E_DM_FAILTOCONNECTTOBITS", "The download manager was unable to connect to the Background Intelligent Transfer Service (BITS).", "Check the BITS service on the device."),
    0x8024A10A: ("USO_E_SERVICE_SHUTTING_DOWN", "The Windows Update service is shutting down.", "The service stopped mid-operation; retry."),
    0x800F081F: ("CBS_E_SOURCE_MISSING", "The source for the package or file was not found.", "Windows servicing could not find required source files; check component store health."),
    0x800F0823: ("CBS_E_NEW_SERVICING_STACK_REQUIRED", "The package requires a newer version of the servicing stack.", "Install the latest servicing stack / cumulative update first."),
    0x800F0831: ("CBS_E_STORE_CORRUPTION", "The component store is corrupted.", "A prerequisite update is missing or the store is damaged; repair with DISM."),
    0x800F0922: ("CBS_E_INSTALLERS_FAILED", "Processing advanced installers and generic commands failed.", "Commonly low space on the System Reserved partition or a network dependency during install."),
}

HTTP_STATUS: dict[int, tuple[str, str]] = {
    400: ("Bad Request", "The request was malformed."),
    401: ("Unauthorized", "Credentials were missing or rejected."),
    403: ("Forbidden", "Authenticated but not allowed."),
    404: ("Not Found", "The resource does not exist at that URL."),
    407: ("Proxy Authentication Required", "A proxy between the machine and the target requires credentials."),
    408: ("Request Timeout", "The server gave up waiting for the request."),
    409: ("Conflict", "The request conflicts with the current state of the resource."),
    429: ("Too Many Requests", "Rate limited by the server."),
    500: ("Internal Server Error", "The server failed while handling the request."),
    502: ("Bad Gateway", "A proxy or gateway got an invalid response upstream."),
    503: ("Service Unavailable", "The service was temporarily unavailable."),
    504: ("Gateway Timeout", "A proxy or gateway timed out waiting upstream."),
}

_FACILITY_WIN32 = 0x8007

_HRESULT_HEX = re.compile(r"(?<![0-9A-Za-z])0x(8[0-9A-Fa-f]{7})(?![0-9A-Fa-f])")
_NEGATIVE_HRESULT = re.compile(r"(?<![\w.])-(21\d{8})(?!\d)")
_ADAPTIVA_CODE = re.compile(r"Error Code = (-?\d+) \((0x[0-9A-Fa-f]+)\)")
_EXIT_CONTEXT = re.compile(
    r"(?i)\b(?:exit[ _-]?code|exitcode|return[ _-]?code|returncode|result[ _-]?code|"
    r"exit[ _-]?status|returned actual error code|error code)\b"
    r"\s*(?:is|was|of|=|:)?\s*[\[(]?\s*(-?\d{1,10})\b"
)
_MSI_STATUS = re.compile(r"(?i)\berror status:\s*(\d{1,6})\b")
_MSI_RETURN_VALUE = re.compile(r"\bReturn value (\d)\.")
_HTTP_CONTEXT = re.compile(
    r"(?i)\b(?:status code|http status|http error|returned|status)\s*[:=]?\s*\[?\s*(\d{3})\b"
)


@dataclass(frozen=True)
class DecodedCode:
    """One error code found in log text, decoded where the value is known."""

    kind: str  # hresult | exit_code | http_status | msi_action_result | adaptiva
    value: int
    raw: str
    name: str | None = None
    meaning: str | None = None
    hint: str | None = None

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.value}"

    @property
    def is_success(self) -> bool:
        if self.kind == "exit_code":
            return self.value in SUCCESS_CODES
        if self.kind == "msi_action_result":
            return self.value in (0, 1)
        if self.kind == "http_status":
            return self.value < 400
        return False

    def display(self) -> str:
        if self.kind == "hresult":
            return f"0x{self.value:08X}"
        return str(self.value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.display(),
            "kind": self.kind,
            "name": self.name,
            "meaning": self.meaning,
            "hint": self.hint,
            "success": self.is_success,
        }


def decode_hresult(value: int, raw: str | None = None) -> DecodedCode:
    value &= 0xFFFFFFFF
    raw = raw or f"0x{value:08X}"
    if value in HRESULT_CODES:
        name, meaning, hint = HRESULT_CODES[value]
        return DecodedCode("hresult", value, raw, name, meaning, hint)
    if (value >> 16) == _FACILITY_WIN32:
        win32 = value & 0xFFFF
        if win32 in WIN32_CODES:
            name, meaning, hint = WIN32_CODES[win32]
            return DecodedCode(
                "hresult", value, raw, f"HRESULT_FROM_WIN32({name})", meaning, hint
            )
        return DecodedCode(
            "hresult", value, raw, f"HRESULT_FROM_WIN32({win32})", f"Win32 error {win32}.", None
        )
    if (value >> 16) == 0x8024:
        return DecodedCode("hresult", value, raw, "WU_E_*", "Windows Update Agent error.", None)
    if (value >> 16) == 0x800F:
        return DecodedCode("hresult", value, raw, "CBS_E_*", "Windows component servicing error.", None)
    return DecodedCode("hresult", value, raw)


def decode_exit_code(value: int, raw: str | None = None) -> DecodedCode:
    raw = raw or str(value)
    if value < 0 or value > 0xFFFF:
        return decode_hresult(value, raw)
    if value in WIN32_CODES:
        name, meaning, hint = WIN32_CODES[value]
        return DecodedCode("exit_code", value, raw, name, meaning, hint)
    return DecodedCode("exit_code", value, raw)


def decode_http_status(value: int, raw: str | None = None) -> DecodedCode:
    name, meaning = HTTP_STATUS.get(value, (None, None))
    return DecodedCode("http_status", value, raw or str(value), name, meaning)


def decode_any(text: str) -> DecodedCode | None:
    """Decode a user-supplied code: ``0x80070643``, ``-2147467259``, ``1603``, ``http 407``."""
    value = (text or "").strip().lower()
    if not value:
        return None
    http = re.fullmatch(r"http\s*(\d{3})", value)
    if http:
        return decode_http_status(int(http.group(1)), text)
    try:
        if value.startswith("0x"):
            number = int(value, 16)
            return decode_hresult(number, text) if number > 0xFFFF else decode_exit_code(number, text)
        number = int(value)
    except ValueError:
        return None
    if number < 0:
        return decode_hresult(number, text)
    return decode_exit_code(number, text)


def extract_codes(text: str) -> list[DecodedCode]:
    """Every distinct error code in ``text``, decoded. Order follows first appearance."""
    if not text:
        return []
    found: list[tuple[int, DecodedCode]] = []
    taken: list[tuple[int, int]] = []

    def overlaps(span: tuple[int, int]) -> bool:
        return any(span[0] < end and start < span[1] for start, end in taken)

    for match in _ADAPTIVA_CODE.finditer(text):
        taken.append(match.span())
        number = int(match.group(1))
        found.append(
            (
                match.start(),
                DecodedCode(
                    "adaptiva",
                    number,
                    match.group(0),
                    None,
                    "Adaptiva internal error code (not a Windows error).",
                ),
            )
        )
    for match in _HRESULT_HEX.finditer(text):
        taken.append(match.span())
        found.append((match.start(), decode_hresult(int(match.group(1), 16), match.group(0))))
    for match in _NEGATIVE_HRESULT.finditer(text):
        number = -int(match.group(1))
        if number < -0x80000000:
            continue
        taken.append(match.span())
        found.append((match.start(), decode_hresult(number, match.group(0))))
    for match in _MSI_RETURN_VALUE.finditer(text):
        taken.append(match.span())
        number = int(match.group(1))
        meaning = {
            0: "Action not executed.",
            1: "Action succeeded.",
            2: "User cancelled.",
            3: "Fatal error in this action.",
        }.get(number)
        found.append(
            (match.start(), DecodedCode("msi_action_result", number, match.group(0), None, meaning))
        )
    for pattern in (_MSI_STATUS, _EXIT_CONTEXT):
        for match in pattern.finditer(text):
            span = match.span(1)
            if overlaps(match.span()):
                continue
            taken.append(span)
            found.append((match.start(), decode_exit_code(int(match.group(1)), match.group(0))))
    for match in _HTTP_CONTEXT.finditer(text):
        if overlaps(match.span()):
            continue
        number = int(match.group(1))
        if number in HTTP_STATUS:
            taken.append(match.span())
            found.append((match.start(), decode_http_status(number, match.group(0))))

    seen: set[str] = set()
    ordered: list[DecodedCode] = []
    for _, code in sorted(found, key=lambda item: item[0]):
        if code.key in seen:
            continue
        seen.add(code.key)
        ordered.append(code)
    return ordered
