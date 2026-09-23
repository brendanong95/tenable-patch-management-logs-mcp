"""What each TPM log records, known error signatures, playbooks and advisories.

Every known issue carries a ``confidence``:

* ``documented`` - described by Tenable or Adaptiva; ``source`` links to it.
* ``observed``   - seen in real TPM 10.2.973.9 logs; the explanation is derived from
  the message text and the surrounding log lines.
* ``generic``    - a standard Java, Windows, SQL or network error with a well-known
  meaning that is not specific to TPM.

``impact`` drives ranking; ``none`` marks platform noise that summaries set aside by
default (it is still counted, never silently dropped).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# --------------------------------------------------------------------------- #
# Sources
# --------------------------------------------------------------------------- #

SOURCES: dict[str, str] = {
    "tenable_client_logs": "https://docs.tenable.com/integrations/Tenable-Patch-Management/Content/ts-client-logs.htm",
    "tenable_server_logs": "https://docs.tenable.com/integrations/Tenable-Patch-Management/Content/ts-server-logs.htm",
    "tenable_client_install_logs": "https://docs.tenable.com/integrations/Tenable-Patch-Management/Content/client-install-logs.htm",
    "tenable_client_validator": "https://docs.tenable.com/integrations/Tenable-Patch-Management/Content/client-validator.htm",
    "tenable_server_install": "https://docs.tenable.com/integrations/Tenable-Patch-Management/Content/server-installation.htm",
    "tenable_admin_portal_logs": "https://docs.tenable.com/integrations/Tenable-Patch-Management/Content/express-ld/getting-started.htm",
    "tenable_release_notes_2025": "https://docs.tenable.com/release-notes/Content/patch-management/2025.htm",
    "tenable_release_notes_2026": "https://docs.tenable.com/release-notes/Content/patch-management/2026.htm",
    "adaptiva_logging_config": "https://support.adaptiva.com/hc/en-us/articles/38137478589709-Modifying-the-Adaptiva-Logging-Configuration",
    "adaptiva_services_sensor_92": "https://support.adaptiva.com/hc/en-us/articles/37731460124429-Patches-show-as-Failed-due-to-Services-sensor-error-in-OneSite-Patch-9-2",
    "adaptiva_client_upgrade_965": "https://support.adaptiva.com/hc/en-us/articles/31519727703949-Adaptiva-Client-upgrade-completes-successfully-but-ClientService-fails-to-start",
    "adaptiva_known_issues_10_0_971": "https://support.adaptiva.com/hc/en-us/articles/43750967019149-Known-Issues-10-0-971-Issues",
    "adaptiva_feature_updates": "https://docs.adaptiva.com/patch/scenarios/feature-updates",
    "adaptiva_client_validator": "https://docs.adaptiva.com/platform-guide/client-management/client-validator",
    "observed": "Observed in real Tenable Patch Management 10.2.973.9 logs (SaaS server bundle and a Windows client).",
}

# --------------------------------------------------------------------------- #
# Log catalog
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class LogInfo:
    """Purpose of one log file, which can differ between client and server."""

    name: str
    client: str | None = None
    server: str | None = None
    setup: str | None = None
    source: str = "tenable_client_logs"

    @property
    def scope(self) -> str:
        roles = [role for role, text in (("client", self.client), ("server", self.server), ("setup", self.setup)) if text]
        if "client" in roles and "server" in roles:
            return "both"
        return roles[0] if roles else "unknown"

    def purpose(self, role: str | None = None) -> str | None:
        if role == "server":
            return self.server or self.client or self.setup
        if role == "setup":
            return self.setup or self.client or self.server
        return self.client or self.server or self.setup

    def to_dict(self, role: str | None = None) -> dict[str, Any]:
        data: dict[str, Any] = {"log": self.name, "scope": self.scope}
        if role:
            data["purpose"] = self.purpose(role)
        else:
            data.update({k: v for k, v in (("client", self.client), ("server", self.server), ("setup", self.setup)) if v})
        data["source"] = SOURCES.get(self.source, self.source)
        return data


def _both(name: str, client: str, server: str) -> LogInfo:
    return LogInfo(name, client=client, server=server, source="tenable_client_logs")


def _client(name: str, purpose: str) -> LogInfo:
    return LogInfo(name, client=purpose, source="tenable_client_logs")


def _server(name: str, purpose: str, source: str = "tenable_server_logs") -> LogInfo:
    return LogInfo(name, server=purpose, source=source)


_CATALOG_ENTRIES: tuple[LogInfo, ...] = (
    # --- main logs, client and server ---------------------------------------
    _both("adaptiva.err", "Errors raised while the tenable-patch-client service runs. Check this first.",
          "Errors raised while the tenable-patch-server service runs. Check this first."),
    _both("adaptiva.log", "Main client service log; almost everything the client does is written here.",
          "Main server service log; almost everything the server does is written here."),
    _both("AdaptivaNativeUtils.log", "Native Windows access made by the client service.",
          "Native Windows access made by the server service."),
    _both("AdaptivaNativeUtilX.log", "FIPS cryptography operations using OpenSSL.",
          "FIPS cryptography operations using OpenSSL."),
    _both("AdaptivaService.log", "Client service start and stop.", "Server service start and stop."),
    _both("AdaptiveProtocolTransport.log", "Data transfers over Adaptive Protocol.",
          "Data transfers over Adaptive Protocol."),
    _both("messagingMonitor.log", "Message counts.", "RVP advertisement logging."),
    _both("revision.properties", "Build timestamp, git commit and version of the installed client.",
          "Build timestamp, git commit and version of the installed server."),
    _both("sqlMonitor.log", "Row counts from the client's local database.", "SQL call monitoring."),
    _both("VCDiff.log", "Building diffs between content versions.", "Building diffs between file versions."),
    _both("VCDiffDecoder.log", "Applying diffs to rebuild updated content.",
          "Applying diffs to rebuild updated content."),
    _client("AdaptivaClientValidator.log", "Output of the Client Validator connectivity checks."),
    LogInfo("ClientValidatorResults.txt",
            client="Client Validator pass/fail results (check.* values under HKLM\\SOFTWARE\\Adaptiva\\client), "
                   "exported by collect/Collect-TPMLogs.ps1.",
            source="adaptiva_client_validator"),
    _client("AdaptivaRemoteInstallLog.log", "Intune edition: peer-to-peer content download started from Intune."),
    _client("AdaptivaServiceRestart.log", "Restart helper used during client install and upgrade."),
    _client("AdaptivaWindowsUpdateHelper.log", "Windows Update helper process used for patching."),
    _server("AdaptivaServerNativeUtils.log", "Native library calls for SMB connections and network file systems."),
    _server("ntlmauth.log", "NTLM and Kerberos authentication to SQL Server (on-prem servers)."),
    LogInfo("hs_err_pid.log", client="Java runtime crash report written when the client service crashes.",
            server="Java runtime crash report written when the server service crashes.",
            source="tenable_release_notes_2026"),
    # --- client component logs ----------------------------------------------
    _client("_SDMErrors.log", "Errors deploying patches. The first log to open for failed installs."),
    _client("ActionExec.log", "Action executions."),
    _client("PatchingAdmin.log", "Scan results (installed / not installed), maintenance windows and patching decisions."),
    _client("PatchingPolicyClient.log", "Patching policies arriving from the server and changes to them."),
    _client("PatchNotifier.log", "Desktop notifications shown to users about patching."),
    _client("LinuxPatching.log", "Linux package scanning and patch deployment."),
    _client("BlobSystem.log", "Internal blob download system."),
    _client("BRP2PDownload.log", "Byte-range peer-to-peer downloads for Windows Update and Microsoft 365."),
    _client("BRP2PDownloadTrace.log", "Which source (CDN or which peer) served each byte range."),
    _client("BRP2PUpload.log", "Byte-range uploads to peers."),
    _client("BRP2PUploadTrace.log", "Which peer received each byte-range block."),
    _client("ContentCache.log", "Content cache state, including free disk space checks."),
    _client("ContentDeleter.log", "Deleting content from the cache."),
    _client("ContentDownload.log", "Every content download."),
    _client("ContentLockManager.log", "Peer-to-peer locking while content downloads."),
    _client("ContentPush.log", "Content pre-staging and push."),
    _client("ContentUnpack.log", "Unpacking downloaded content."),
    _client("ContentUpload.log", "Uploading content to other clients."),
    _client("DownloadCompleted.log", "Details of completed downloads."),
    _client("PatchContentDownloader.log", "Downloads for non-Windows patches."),
    _client("PolicyManager.log", "Policy processing on the client."),
    _client("ClientInfo.log", "Client registration and the IP address the client uses."),
    _client("HttpTransport.log", "HTTP transport used when the client binds to the server URL."),
    _client("InternetPeer.log", "Communication details for internet-based clients."),
    _client("NatTraversal.log", "NAT traversal protocol details."),
    _client("NetworkLocation.log", "Current network location (for example ON_PREMISES or INTERNET)."),
    _client("P2PDiscovery.log", "Peer-to-peer content discovery."),
    _client("P2PDiscoveryCache.log", "Caching of peer-to-peer discovery results."),
    _client("P2PStore.log", "Local peer-to-peer store activity."),
    _client("RelayTrackingClient.log", "Cloud relay routing for internet clients."),
    _client("RelayTrackingServer.log", "Cloud relay message receipts."),
    _client("ServerLocator.log", "Finding and binding to the server."),
    _client("SmallMsgTransport.log", "Small UDP message transport."),
    _client("SentRecvMsg.log", "All messages between client and server, and between clients."),
    _client("LargeMsgTransport.log", "Large message transport (AdaptiveTransport)."),
    _client("Messaging.log", "Messaging ports starting and stopping."),
    _client("Inventory.log", "Inventory collection and reporting."),
    _client("IPC.log", "Inter-process communication between the client service and other processes."),
    _client("RegIPC.log", "Registry-based inter-process communication."),
    _client("MemoryCache.log", "In-memory cache (CachedHashMap) activity."),
    _client("Locking.log", "Concurrency locking."),
    _client("Scheduler.log", "Scheduler activity."),
    _client("Security.log", "ACL updates."),
    _client("Configuration.log", "System configuration changes on the client."),
    _client("ClientSetupChecks.log", "Client setup checks, also written by the Client Validator."),
    _client("CacheMigrationClient.log", "Cache migration tool."),
    _client("CHSClient.log", "Client health modules."),
    _client("SoftwareDeploymentManager.log", "Patch deployment creation, progress and problems."),
    _client("SoftwareInstaller.log", "Software installation status and installer exit codes."),
    _client("SoftwareRelationshipManager.log", "Dependencies between software items."),
    _client("ObjectDeployment.log", "Object deployment system."),
    _client("RemoteWorkflowExecution.log", "Workflows run on the client by the Tool Foundry."),
    _client("WorkflowSystem.log", "General workflow logging on the client."),
    _client("Office365.log", "Office / Microsoft 365 patch installation."),
    _client("OfficeLockManager.log", "Office-level locking (IntelliStage)."),
    _client("SensorExec.log", "System query sensor execution."),
    _client("Telemetry.log", "On-demand client queries."),
    _client("TFTP.log", "TFTP for PXE boot."),
    _client("PXE.log", "PXE service availability."),
    _client("WOL.log", "Wake-on-LAN activity."),
    _client("WIFI.log", "Wi-Fi office transitions."),
    _client("VirtualSMP.log", "Virtual state migration point activity."),
    _client("RVPOSDSupporter.log", "RVP content requests for OS deployment."),
    _client("RVPState.log", "Local subnet RVP state."),
    _client("MKDCHandler.log", "Fatal error handling."),
    _client("UserPortal.log", "The separate user portal service for user actions."),
    _client("FileDeletion.log", "Non-content file deletion requests."),
    _client("SQLAccess.log", "Local client database activity."),
    _client("SparseFileSystem.log", "Sparse file reads and writes in the content cache."),
    _client("Startup.log", "Client startup and shutdown."),
    # --- names shared by client and server component logs --------------------
    _both("Patching.log", "Scan statuses and maintenance windows.", "Miscellaneous patching logs."),
    _both("WindowsPatching.log", "Windows Update and Office 365 scan and install progress.",
          "Progress and results of scans and patches for Windows Update and Office 365."),
    _both("DeltaSeries.log", "Downloading and assembling delta series content.",
          "Tracking delta series content (content whose earlier version may already exist)."),
    _both("Feeds.log", "Feeds arriving, dependency checks, consumption and removal.",
          "Feed instructions received from the Operations Manager and their distribution to clients."),
    _both("HTTP.log", "Health of the client's HTTP clients and connection managers.",
          "Health of the server's HTTP clients and connection managers."),
    _both("License.log", "Client license status.", "Status of the licenses enabled on the server."),
    _both("MemoryManager.log", "Client memory state and changes.", "Server memory usage and changes."),
    _both("P2PRing.log", "Peer-to-peer ring used for status messages.",
          "Peer-to-peer ring used to upload status messages from clients."),
    _both("RelayDetailed.log", "Detailed relay connectivity and security.",
          "Detailed relay connectivity and security protocols over HTTP."),
    _both("RelaySimple.log", "Overview of relay handshakes and messaging.",
          "Overview of handshakes and HTTP messaging."),
    _both("ClientUpgrade.log", "Client auto-upgrade.", "Client auto-upgrade system."),
    _both("WorkflowStatus.log", "Workflow execution status, progress and errors.",
          "Execution status, progress and errors of workflow invocations."),
    _both("SensorOfflineCache.log", "Scheduled offline data collection.",
          "Scheduled data collection on clients, uploaded to the server as diffs."),
    _both("OperationsManagerRequests.log", "Requests to the Operations Manager.",
          "Requests sent to the Operations Manager."),
    _both("PayloadActivation.log", "Policy payloads arriving and being activated.",
          "Policy payloads from the server pending activation."),
    _both("SQLUploader.log", "Uploading SQL data.", "Bulk data payloads sent to the server for insertion."),
    _both("ThreadInfo.log", "Thread state dumps when enabled.",
          "Thread state dumps when slm.logthreadstates is enabled."),
    _both("Utils.log", "Generic utilities.", "Generic utilities."),
    # --- server component logs ------------------------------------------------
    _server("Akka.log", "The server's REST API (used by the Admin Portal)."),
    _server("BlobServer.log", "Internal blob download system."),
    _server("BlobVersionAuditor.log", "Blob system auditing (used with Microsoft Configuration Manager)."),
    _server("ByteLevelP2PPublisher.log", "Publishing content with the byte-range peer-to-peer protocol."),
    _server("CdnService.log", "Anything to do with accessing the CDN service."),
    _server("ContentSQLQuery.log", "Content receipts."),
    _server("IntentHistory.log", "Server-side changes to Intent Schema objects."),
    _server("MASFileActivity.log", "Direct content uploads from MAS to the public CDN."),
    _server("MetadataCommon.log", "CVE mapping updates for metadata objects."),
    _server("MetadataOperations.log", "Patch blocklisting operations."),
    _server("MultiTenancy.log", "Tenants created, updated and deleted on multi-tenant systems."),
    _server("PatchingApprovals.log", "Patch approvals being created or updated."),
    _server("PatchingStatusCollection.log", "Patch statuses received from clients and written to the database."),
    _server("Provisioning.log", "Server activation through the Operations Manager, and content URL computation."),
    _server("RestApiFoundry.log", "Requests and authentication for the REST API Foundry."),
    _server("SqlDataProvider.log", "Authoring and running SQL for dashboards."),
    _server("TwilioSendGrid.log", "Calls to third-party communication providers."),
    _server("UserDashboardSubscription.log", "Dashboard exports to Excel."),
    _server("VulnerabilityManagement.log", "Vulnerability data received from integrations (Tenable VM / Security Center)."),
    _server("WebUINotifications.log", "Notifications exchanged with the Admin Portal web UI."),
    _server("CloudInstanceManagement.log",
            "Cloud tenant instance management calls. Seen in SaaS server bundles; not in Tenable's log list.",
            source="observed"),
    # --- setup logs -------------------------------------------------------------
    LogInfo("AdaptivaClientSetup.log", setup="Client installation (%windir%\\AdaptivaSetupLogs\\Client).",
            source="tenable_client_install_logs"),
    LogInfo("AdaptivaP2PClientSetup.log", setup="Client installation from the P2P MSI.",
            source="tenable_client_install_logs"),
    LogInfo("AdaptivaServerSetup.log", setup="Server installation (%windir%\\AdaptivaSetupLogs\\Server).",
            source="tenable_server_install"),
    LogInfo("AdaptivaClientdService.log", client="Linux: exported journalctl output for adaptivaclientd.service.",
            source="tenable_client_install_logs"),
    # --- folders ------------------------------------------------------------------
    LogInfo("msilogs", client="Windows Installer logs, one per MSI-based patch (<productid>_<download id>.log).",
            source="tenable_client_logs"),
    LogInfo("workflowlogs", client="Workflow execution logs (<workflow name>_<id>_<sequence>.log).",
            server="Server and business workflow execution logs (<workflow name>_<id>_<sequence>.log).",
            source="tenable_server_logs"),
)

LOG_CATALOG: dict[str, LogInfo] = {info.name.lower(): info for info in _CATALOG_ENTRIES}

#: Logs whose name alone says which side of the product wrote them.
SERVER_ONLY_LOGS = frozenset(key for key, info in LOG_CATALOG.items() if info.scope == "server")
CLIENT_ONLY_LOGS = frozenset(key for key, info in LOG_CATALOG.items() if info.scope == "client")
SETUP_LOGS = frozenset(key for key, info in LOG_CATALOG.items() if info.scope == "setup")

# --------------------------------------------------------------------------- #
# Known issues
# --------------------------------------------------------------------------- #

IMPACT_ORDER = {"high": 0, "medium": 1, "low": 2, "none": 3}


@dataclass(frozen=True)
class KnownIssue:
    """A recognisable log signature with an explanation and a fix."""

    id: str
    title: str
    pattern: re.Pattern[str]
    category: str
    impact: str
    explanation: str
    remediation: str
    confidence: str
    applies_to: str = "both"
    source: str = "observed"

    @property
    def is_noise(self) -> bool:
        return self.impact == "none"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "impact": self.impact,
            "noise": self.is_noise,
            "explanation": self.explanation,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "applies_to": self.applies_to,
            "source": SOURCES.get(self.source, self.source),
        }


def _issue(id: str, title: str, pattern: str, category: str, impact: str, explanation: str,
           remediation: str, confidence: str, applies_to: str = "both", source: str = "observed") -> KnownIssue:
    return KnownIssue(id, title, re.compile(pattern, re.IGNORECASE | re.DOTALL), category, impact,
                      explanation, remediation, confidence, applies_to, source)


#: Checked in order; put specific signatures before generic ones.
KNOWN_ISSUES: tuple[KnownIssue, ...] = (
    # --- documented --------------------------------------------------------------
    _issue(
        "services_sensor_missing_dll",
        "Services sensor fails: InventoryAgentNativeCode.dll missing (9.2 new installs)",
        r"UnsatisfiedLinkError.{0,300}WinNTServiceInventoryAgent",
        "patching", "high",
        "Known issue on new 9.2 client installs: the Services sensor fails with UnsatisfiedLinkError because "
        "InventoryAgentNativeCode.dll is missing. Patches that check or restart a service after installing are "
        "marked Failed and retried up to five times, even when the install itself worked.",
        "Upgrade the client to a build that includes the DLL. Adaptiva's documented workaround is to copy "
        "InventoryAgentNativeCode.dll into the client's bin folder and restart the client service, then use "
        "Reset Deployment Failures for the device and rescan it.",
        "documented", source="adaptiva_services_sensor_92",
    ),
    _issue(
        "client_upgrade_virtual_mode_failed",
        "Client upgrade fails in Virtual Mode (9.1.965.4 / 9.1.965.9)",
        r"Virtual Mode upgrade failed with an error.{0,400}PatchDeploymentResultStore",
        "client_upgrade", "high",
        "Known issue when manually upgrading clients to 9.1.965.4 or 9.1.965.9: the upgrade cannot migrate "
        "PatchDeploymentResultStore objects from the local database, and the client service does not start.",
        "Upgrade the client to 9.1.965.12 or later.",
        "documented", source="adaptiva_client_upgrade_965",
    ),
    # --- Tenable VM / Security Center integration ------------------------------------
    _issue(
        "tvm_invalid_credentials",
        "Tenable integration rejected: invalid API keys (HTTP 401)",
        r"Tenable returned 401 UNAUTHORIZED for access key",
        "integration", "high",
        "TPM called Tenable Vulnerability Management with the configured API keys and got HTTP 401 'Invalid "
        "credentials'. No vulnerability data is imported while this continues.",
        "Generate new API keys in Tenable VM (Settings > My Account > API Keys, ideally for a dedicated "
        "service user) and enter both the access key and secret key in TPM's Tenable access settings. Keys "
        "stop working when they are regenerated or the owning user is disabled or deleted.",
        "observed",
    ),
    _issue(
        "tvm_keys_not_linked_to_container",
        "Tenable integration rejected: keys not linked to an active Tenable container",
        r"does not appear to be related to any active containers",
        "integration", "high",
        "Validating TPM's Tenable access settings failed with HTTP 401 and the message 'This scanner, agent, or "
        "API key token does not appear to be related to any active containers on any sites'. Tenable could not "
        "match the keys to any active container.",
        "Re-enter the keys, checking that access and secret key are not swapped or truncated. Confirm the keys "
        "were not regenerated since they were entered, the owning user is still active, and the Tenable site "
        "selected in the access settings (commercial or FedRAMP) is where the keys were created. If in doubt, "
        "generate a fresh key pair.",
        "observed",
    ),
    _issue(
        "tvm_access_settings_missing",
        "Tenable vulnerability import skipped: access settings not configured",
        r"Tenable access settings have not been provided yet",
        "integration", "medium",
        "The scheduled Tenable vulnerability update ran without any Tenable access settings, so no "
        "vulnerability data was requested. Vulnerability-based patching views and bots have no Tenable data. "
        "The update still logs 'completed successfully' because there was nothing to fetch.",
        "Enter Tenable VM or Security Center API keys in TPM's Tenable access settings. If keys were entered and "
        "this still appears, look for key validation failures (tvm_invalid_credentials, "
        "tvm_keys_not_linked_to_container) around the same time.",
        "observed",
    ),
    # --- feeds, content and CDN ----------------------------------------------------------
    _issue(
        "feed_check_failed",
        "Periodic feed check failed to reach the Operations Manager",
        r"\[Periodic Feed Check\] An exception arose trying to retrieve new Feed instructions",
        "feeds", "medium",
        "The server's periodic feed check could not fetch feed instructions (patch catalog and product "
        "updates) from the Adaptiva Operations Manager. The root cause line shows why, for example a timeout "
        "or DNS failure. New patches and product updates arrive late while this continues.",
        "Single failures are retried automatically; confirm a later '[Periodic Feed Check] Feed instruction "
        "package received successfully.' follows. If failures persist on-prem, allow outbound HTTPS from the "
        "TPM server to services.adaptiva.cloud and *.adaptivacdn.cloud (including proxy settings). On SaaS "
        "this runs on Tenable's side: open a Tenable support case with the time range.",
        "observed",
    ),
    _issue(
        "adaptiva_cloud_dns_failure",
        "Cannot resolve an Adaptiva cloud hostname",
        r"UnknownHostException:\s*[\w.-]*adaptiva(?:cdn)?\.cloud",
        "connectivity", "high",
        "The machine could not resolve an Adaptiva cloud hostname such as services.adaptiva.cloud, so it could "
        "not reach Adaptiva cloud services.",
        "Check DNS on the affected machine (nslookup services.adaptiva.cloud). In SaaS server logs this is on "
        "Tenable's side; open a support case if it persists.",
        "observed",
    ),
    _issue(
        "cdn_content_publication_failed",
        "Content publication to the cloud CDN failed",
        r"Could not publish file .{0,300} to the cloud|failed during cloud store|Error while publishing content with id"
        r"|ContentException while trying to publish Content|BunnyCloudStorage :: Failed to upload",
        "content", "medium",
        "Uploading a content file (for example a Policy_<id> package) to the cloud content store failed. "
        "Clients cannot download that content version until a retry succeeds.",
        "Check for a later successful publication of the same content ID. On SaaS, repeated failures for the "
        "same content are a Tenable-side problem: open a support case with the content ID and timestamps. "
        "On-prem, check outbound HTTPS and proxy access from the server to the CDN endpoints.",
        "observed",
    ),
    _issue(
        "cdn_old_content_delete_failed",
        "Old content version could not be deleted from the CDN",
        r"Failed to remove old file \[.{0,300}\] from the cloud|\[Bunny Storage APIs :: Delete .{0,300}\] Exception thrown deleting file",
        "content", "low",
        "After publishing a newer version, the server could not delete an older content file from the cloud "
        "content store. New content is unaffected; the old file just remains in storage.",
        "Usually harmless. If it repeats for many content IDs, mention it in a Tenable support case (SaaS) or check "
        "CDN access from the server (on-prem).",
        "observed",
    ),
    _issue(
        "cdn_service_build_failed",
        "CDN service could not be initialised",
        r"\[CDN Service :: Instance Acquisition\] An exception was thrown attempting to build the CDN service",
        "content", "medium",
        "The server could not obtain CDN settings or build its CDN client, so content transfers through the CDN "
        "were unavailable until the next successful attempt.",
        "Check for a later '[CDN Service :: Instance Acquisition] Settings retrieved successfully' line. Persistent "
        "failures on SaaS need a Tenable support case; on-prem, check outbound HTTPS to the Adaptiva cloud services.",
        "observed",
    ),
    # --- clients and messaging -------------------------------------------------------------
    _issue(
        "client_install_auth_missing",
        "Client registration rejected: install authentication missing",
        r"All Client install authentication enabled, install attempted without auth information",
        "client_install", "medium",
        "A device tried to register as a new client, but client install authentication is enabled and the "
        "install did not include the authentication information, so the server rejected it. The IP address at "
        "the end of the message identifies the device.",
        "Reinstall the client on that device with the install command or package from the TPM console that "
        "includes the install authentication details.",
        "observed",
    ),
    _issue(
        "server_message_retries",
        "Server message to a client keeps being retried",
        r"The message has been retried \d+ times",
        "connectivity", "low",
        "The server keeps retrying a message (for example ContentDeletion or PolicyAssignment) that a client has "
        "not acknowledged. The Receiver ID in the message is the client ID.",
        "Check whether that client is online and connected (diagnose client_connectivity lists the client IDs). "
        "Retries to decommissioned devices are harmless but noisy; remove stale devices from TPM.",
        "observed",
    ),
    _issue(
        "client_server_channel_closed",
        "Client lost its HTTP/2 connection to the TPM server",
        r"(?:Unable to send|Failed to check alive status of server).{0,400}ConnectionClosedException",
        "connectivity", "low",
        "The client's HTTP/2 connection to the TPM server closed while it was sending or checking the server. "
        "An occasional occurrence (sleep, network change) is normal and the client reconnects.",
        "If it happens often, look for proxies, TLS inspection or firewalls with short idle timeouts between the "
        "device and the server URL, and run the Client Validator on the device "
        "(%ADAPTIVACLIENT%\\bin\\AdaptivaClientValidator.exe).",
        "observed",
    ),
    _issue(
        "client_mac_unknown",
        "Server has no MAC address for a client",
        r"MAC address not known for client",
        "connectivity", "low",
        "The server has no MAC address recorded for this client ID, so features that rely on it (such as "
        "Wake-on-LAN) cannot target the device.",
        "Usually harmless. If Wake-on-LAN matters for this device, check that the client reports its hardware "
        "inventory.",
        "observed",
    ),
    _issue(
        "sensor_expression_warnings",
        "Product detection sensor raised warnings",
        r"During evaluation of expression \[.*\], \d+ warnings? (?:were|was) generated",
        "patching", "low",
        "A product-detection sensor expression raised warnings, typically because the registry key or file it "
        "looks for does not exist on this device (the product is not installed).",
        "Harmless unless the related product shows as Failed or Unknown for this device; in that case search for "
        "the product name around the same time.",
        "observed",
    ),
    _issue(
        "akka_closed_channel",
        "Admin Portal REST connection closed by the caller",
        r"Closed channel on completed response",
        "platform", "low",
        "The server's REST layer (used by the Admin Portal) closed a connection after the response completed, "
        "typically because the browser or API caller went away.",
        "Usually harmless. Investigate only if users report the Admin Portal failing to load at the same times.",
        "observed",
    ),
    # --- platform noise -------------------------------------------------------------
    _issue(
        "sqlserver_proc_on_postgres",
        "SQL Server monitoring query run against PostgreSQL (SaaS noise)",
        r"EXEC \[dbo\]\.\[prc_get_database_statistics\]",
        "platform_noise", "none",
        "The server's SQL monitor calls a SQL Server stored procedure (EXEC [dbo].[prc_get_database_statistics]) "
        "on a PostgreSQL database, which rejects the syntax. It recurs in TPM SaaS server logs and does not "
        "affect patching.",
        "No action needed.",
        "observed", applies_to="saas",
    ),
    _issue(
        "content_receipt_cleanup_noise",
        "Receipt cleanup found nothing to clean (noise)",
        r"Could not find serverContentMetadataObject, while deleting receipts, no in-memory cleanup required",
        "platform_noise", "none",
        "Housekeeping message: while deleting download receipts the server found no matching content metadata, "
        "and as the message says, no cleanup was required.",
        "No action needed.",
        "observed",
    ),
    _issue(
        "http_client_lazy_init_noise",
        "HTTP client built before shared client was ready (noise)",
        r"Shared (?:async )?client is not yet initialized, building and returning new client instead",
        "platform_noise", "none",
        "An HTTP client was requested before the shared client finished initialising, so a new client was "
        "built instead. The request itself proceeds.",
        "No action needed.",
        "observed",
    ),
    _issue(
        "query_no_results_noise",
        "Query returned no results (noise)",
        r"^No results found (?:after filtering|from invocation)",
        "platform_noise", "none",
        "A data query returned no rows.",
        "No action needed.",
        "observed",
    ),
    # --- generic Java / Windows / SQL / network -------------------------------------------
    _issue(
        "sqlserver_login_failed",
        "SQL Server login failed",
        r"Login failed for user",
        "database", "high",
        "The service could not log in to SQL Server with its configured account.",
        "On-prem: check the account the TPM server uses for SQL Server (NTLM or Kerberos, see ntlmauth.log), "
        "its password, and that it still has access to the Adaptiva database.",
        "generic", applies_to="onprem",
    ),
    _issue(
        "sqlserver_tcp_failed",
        "Cannot connect to SQL Server over TCP/IP",
        r"The TCP/IP connection to the host .{0,200} has failed",
        "database", "high",
        "The JDBC driver could not open a TCP connection to SQL Server.",
        "On-prem: check SQL Server is running, TCP/IP is enabled, the port is reachable from the TPM server and "
        "no firewall blocks it.",
        "generic", applies_to="onprem",
    ),
    _issue(
        "duplicate_key_violation",
        "Database rejected a duplicate key or name",
        r"duplicate key value violates unique constraint|Violation of UNIQUE KEY constraint|Cannot insert duplicate key",
        "database", "low",
        "The database rejected a save because an object with the same unique key already exists, most often an "
        "object created with a name that is already in use.",
        "Rename the object and save again. If it repeats without anyone creating objects, open a support case.",
        "generic",
    ),
    _issue(
        "database_deadlock",
        "Database deadlock",
        r"\bdeadlock",
        "database", "medium",
        "Two database operations blocked each other and one was rolled back.",
        "Occasional deadlocks are retried. Frequent ones: on-prem check SQL Server load and maintenance; on SaaS "
        "open a support case with the timestamps.",
        "generic",
    ),
    _issue(
        "jvm_out_of_memory",
        "Java service ran out of memory",
        r"OutOfMemoryError",
        "service", "high",
        "The TPM Java service exhausted its memory. The service usually becomes unstable or restarts.",
        "Look for a service restart shortly after (diagnose service_health). On-prem, check server memory and "
        "load; on SaaS open a support case. On clients, check the device's available memory.",
        "generic",
    ),
    _issue(
        "disk_full",
        "Disk full",
        r"There is not enough space on the disk|No space left on device",
        "service", "high",
        "A write failed because the disk is full.",
        "Free space on the affected drive. On servers, logs and the content library grow over time (Tenable "
        "recommends installing the on-prem server off the OS drive).",
        "generic",
    ),
    _issue(
        "access_denied",
        "Access denied",
        r"AccessDeniedException|Access is denied",
        "service", "medium",
        "The service was denied access to a file, folder or registry location.",
        "Check security software exclusions and permissions for the TPM installation and content folders.",
        "generic",
    ),
    _issue(
        "tls_trust_failure",
        "TLS handshake or certificate trust failure",
        r"PKIX path building failed|unable to find valid certification path|SSLHandshakeException",
        "connectivity", "high",
        "A TLS connection failed because the certificate chain could not be validated or the handshake failed, "
        "commonly caused by TLS inspection proxies or a missing root certificate.",
        "Exclude the TPM server and Adaptiva cloud URLs from TLS inspection, or make sure the inspecting proxy's "
        "root certificate is trusted.",
        "generic",
    ),
    _issue(
        "proxy_auth_required",
        "Proxy authentication required (HTTP 407)",
        r"Proxy Authentication Required|\b407\b.{0,40}proxy",
        "connectivity", "high",
        "A proxy between this machine and the target requires authentication the service did not provide.",
        "Allow the TPM service (running as SYSTEM or the service account) through the proxy without "
        "authentication, or configure proxy credentials.",
        "generic",
    ),
    _issue(
        "dns_failure",
        "DNS resolution failed",
        r"UnknownHostException|Temporary failure in name resolution|No such host is known",
        "connectivity", "high",
        "A hostname could not be resolved.",
        "Check DNS configuration and resolution for the hostname in the message from the affected machine.",
        "generic",
    ),
    _issue(
        "connection_refused",
        "Connection refused",
        r"Connection refused",
        "connectivity", "medium",
        "The target host actively refused the connection: nothing was listening on that port, or a firewall "
        "rejected it.",
        "Check the target service is running and the port is reachable from this machine.",
        "generic",
    ),
    _issue(
        "network_timeout",
        "Network request timed out",
        r"TimeoutValueException|SocketTimeoutException|ConnectTimeoutException|Read timed out|connect timed out",
        "connectivity", "medium",
        "A network request did not complete within its timeout.",
        "Occasional timeouts are retried. If they cluster, check network path, proxy and firewall latency to the "
        "target in the message.",
        "generic",
    ),
    _issue(
        "connection_reset",
        "Connection reset by the other side",
        r"Connection reset",
        "connectivity", "low",
        "The remote side or something in between reset the connection.",
        "Usually transient. If frequent, check proxies, load balancers or firewalls with idle timeouts.",
        "generic",
    ),
)

KNOWN_ISSUES_BY_ID: dict[str, KnownIssue] = {issue.id: issue for issue in KNOWN_ISSUES}

# --------------------------------------------------------------------------- #
# Playbooks
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Playbook:
    """A symptom: which logs and components to read, and what to look for."""

    id: str
    title: str
    summary: str
    roles: tuple[str, ...]
    logs: tuple[str, ...]
    components: tuple[str, ...] = ()
    issue_ids: tuple[str, ...] = ()
    patterns: tuple[str, ...] = ()
    advice: str = ""
    #: Accept this playbook's generic known issues (timeouts, OOM...) from any component.
    generic_issues_anywhere: bool = False
    compiled: tuple[re.Pattern[str], ...] = field(default=(), compare=False, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "summary": self.summary,
            "roles": list(self.roles),
            "logs": list(self.logs),
            "components": list(self.components),
            "known_issues": list(self.issue_ids),
            "advice": self.advice,
        }


def _playbook(**kwargs: Any) -> Playbook:
    patterns = tuple(kwargs.get("patterns", ()))
    return Playbook(**kwargs, compiled=tuple(re.compile(p, re.IGNORECASE) for p in patterns))


PLAYBOOKS: dict[str, Playbook] = {
    playbook.id: playbook
    for playbook in (
        _playbook(
            id="patch_install_failed",
            title="Patch or product update failed to install",
            summary="Deployment results, installer exit codes and Windows Installer failures on clients.",
            roles=("client",),
            logs=("_sdmerrors.log", "softwareinstaller.log", "softwaredeploymentmanager.log", "patchingadmin.log",
                  "windowspatching.log", "linuxpatching.log", "office365.log", "adaptivawindowsupdatehelper.log",
                  "actionexec.log", "msilogs", "adaptiva.err"),
            components=("PatchingAdmin", "SoftwareDeploymentManager", "SoftwareInstaller", "WindowsPatching",
                        "LinuxPatching", "Office365"),
            issue_ids=("services_sensor_missing_dll", "access_denied", "disk_full"),
            patterns=(r"exit ?code", r"return ?code", r"PatchDeploymentResult", r"0x8[0-9a-f]{7}",
                      r"error status:", r"Return value 3", r"reboot (?:required|pending)"),
            advice="Group failures by exit code first. 1603 means the MSI log has the real reason; 0x8024xxxx codes "
                   "come from Windows Update; 3010/1641 are successes that still need a restart.",
        ),
        _playbook(
            id="content_download",
            title="Content stuck downloading, slow, or failing",
            summary="Content, peer-to-peer and CDN download activity on clients.",
            roles=("client",),
            logs=("contentdownload.log", "brp2pdownload.log", "brp2pdownloadtrace.log", "contentlockmanager.log",
                  "blobsystem.log", "contentcache.log", "deltaseries.log", "patchcontentdownloader.log",
                  "adaptiveprotocoltransport.log", "adaptiva.err"),
            components=("ContentDownloadManager", "ContentCache", "BRP2PDownload", "BlobSystem"),
            issue_ids=("network_timeout", "proxy_auth_required", "tls_trust_failure", "dns_failure", "disk_full"),
            patterns=(r"hash", r"mismatch", r"retry", r"\b40[347]\b", r"no (?:peers|source)", r"actualFreeSpace"),
            advice="Check whether bytes come from the CDN or peers (BRP2PDownloadTrace.log), then proxy "
                   "authentication (407), TLS inspection and hash mismatches.",
        ),
        _playbook(
            id="client_connectivity",
            title="Clients not checking in or not receiving work",
            summary="Client-side transport errors and server-side delivery retries and registration rejections.",
            roles=("client", "server"),
            logs=("httptransport.log", "serverlocator.log", "clientinfo.log", "relaysimple.log", "relaydetailed.log",
                  "networklocation.log", "clientsetupchecks.log", "adaptivaclientvalidator.log",
                  "clientvalidatorresults.txt", "adaptiva.err"),
            components=("HttpTransportV2Client", "HttpTransportClient", "ServerLocator", "SendingThread",
                        "NewClientProvider", "ClientDataManager", "HttpServerController"),
            issue_ids=("client_server_channel_closed", "server_message_retries", "client_install_auth_missing",
                       "client_mac_unknown", "tls_trust_failure", "proxy_auth_required", "dns_failure",
                       "connection_refused", "network_timeout"),
            patterns=(r"HTTP connection disconnected", r"Started with binding", r"Passed|Failed"),
            advice="Server retries name the client IDs that are not acknowledging; client logs show why the "
                   "connection drops. Run the Client Validator on affected devices for a pass/fail per check.",
        ),
        _playbook(
            id="vm_integration",
            title="Tenable VM / Security Center integration",
            summary="Access-settings validation, API key failures and vulnerability import runs.",
            roles=("server",),
            logs=("vulnerabilitymanagement.log", "adaptiva.err"),
            components=("TenableClient", "VmIntegrationManager", "VmIntegrationCommonHelper", "TenableVmIntegration",
                        "TenableAssetTagDataManager", "SCAssetListDataManager"),
            issue_ids=("tvm_invalid_credentials", "tvm_keys_not_linked_to_container", "tvm_access_settings_missing"),
            advice="An update that 'completed successfully' while access settings are missing fetched nothing. "
                   "Fix key validation failures first, then confirm detections are being processed.",
        ),
        _playbook(
            id="feeds",
            title="Patch catalog and feed updates",
            summary="Periodic feed checks against the Operations Manager and their root causes.",
            roles=("server",),
            logs=("feeds.log", "adaptiva.err"),
            components=("FeedServer", "PatchingFeedServerConsumer", "FeedUtils", "FeedsNotificationManager"),
            issue_ids=("feed_check_failed", "adaptiva_cloud_dns_failure", "network_timeout", "dns_failure",
                       "tls_trust_failure", "proxy_auth_required"),
            advice="What matters is the time since the last successful feed check, not the failure count.",
        ),
        _playbook(
            id="content_publication",
            title="Content publication to the CDN",
            summary="Uploads of policy and product content to the cloud content store.",
            roles=("server",),
            logs=("cdnservice.log", "provisioning.log", "adaptiva.err"),
            components=("CdnServiceProvider", "BunnyStorageApis", "BunnyCloudStorage", "CloudContentSupporter",
                        "PolicyClientViewGenerator", "PolicyClientViewGeneratorExecutionNode", "LocalContentPublisher"),
            issue_ids=("cdn_content_publication_failed", "cdn_old_content_delete_failed", "cdn_service_build_failed",
                       "network_timeout"),
            advice="A failed publication matters only if the same content ID never publishes successfully later.",
        ),
        _playbook(
            id="service_health",
            title="Service restarts, crashes and memory",
            summary="Service starts (with version), Java crashes, out-of-memory errors and restart loops.",
            roles=("client", "server"),
            logs=("adaptiva.log", "adaptiva.err", "adaptivaservice.log", "adaptivaservicerestart.log",
                  "memorymanager.log", "hs_err_pid.log"),
            components=("Bootstrap", "MemoryManager", "SimpleObjectManager"),
            issue_ids=("jvm_out_of_memory", "disk_full", "access_denied"),
            patterns=(r"Current Version:", r"Shutting down", r"Initializing simple object manager"),
            advice="Several starts in a short window is a restart loop: read the last errors before each start.",
            generic_issues_anywhere=True,
        ),
        _playbook(
            id="database",
            title="Server database problems",
            summary="SQL errors, authentication to SQL Server (on-prem) and deadlocks.",
            roles=("server",),
            logs=("sqlmonitor.log", "ntlmauth.log", "sqldataprovider.log", "adaptiva.err"),
            components=("SQLDataAccessManager", "HibernateUtils", "SqlDataProviderRuntime"),
            issue_ids=("sqlserver_login_failed", "sqlserver_tcp_failed", "database_deadlock",
                       "duplicate_key_violation", "sqlserver_proc_on_postgres"),
            patterns=(r"SQLException|PSQLException|SQLServerException|DataAccessException",),
            advice="On SaaS the database is Tenable-managed: recurring errors there need a support case, except "
                   "known noise such as the SQL Server monitoring query.",
            generic_issues_anywhere=True,
        ),
        _playbook(
            id="client_upgrade",
            title="Client auto-upgrade",
            summary="Client upgrade scheduling, setup failures and the versions seen over time.",
            roles=("client", "server"),
            logs=("clientupgrade.log", "adaptivaservicerestart.log", "adaptivaclientsetup.log",
                  "adaptivap2pclientsetup.log", "msilogs", "adaptiva.err"),
            components=("ClientUpgradeSupporter", "ClientUpgradeDefaultScopeMethods", "Bootstrap"),
            issue_ids=("client_upgrade_virtual_mode_failed",),
            patterns=(r"upgrade", r"Current Version:"),
            advice="MSI 1603 during upgrade is generic; the setup log lines right before it carry the reason.",
        ),
        _playbook(
            id="feature_update_readiness",
            title="Windows feature update not offered or not starting",
            summary="Free disk space checks and 'NOT INSTALLED' scan results for feature updates.",
            roles=("client",),
            logs=("patchingadmin.log", "contentcache.log"),
            components=("PatchingAdmin", "ContentCache"),
            patterns=(r"actualFreeSpace", r"Scanned status \[NOT INSTALLED\]"),
            advice="Feature updates need at least 50 GB free (actualFreeSpace above 52428800000). Also check "
                   "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\CompatMarkers for "
                   "'Blocked' values set to 1.",
        ),
    )
}

#: Minimum free bytes Adaptiva documents for Windows feature updates.
FEATURE_UPDATE_MIN_FREE_BYTES = 52_428_800_000

# --------------------------------------------------------------------------- #
# Version advisories
# --------------------------------------------------------------------------- #


def parse_version(text: str | None) -> tuple[int, ...] | None:
    """``"10.2.973.9"`` -> ``(10, 2, 973, 9)``."""
    if not text:
        return None
    parts = re.findall(r"\d+", text)
    return tuple(int(part) for part in parts[:4]) if len(parts) >= 3 else None


@dataclass(frozen=True)
class VersionAdvisory:
    id: str
    first: str | None
    last: str | None
    fixed_in: str | None
    summary: str
    source: str

    def applies(self, version: str) -> bool:
        parsed = parse_version(version)
        if parsed is None:
            return False
        low = parse_version(self.first) if self.first else None
        high = parse_version(self.last) if self.last else None
        return (low is None or parsed >= low) and (high is None or parsed <= high)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "affected": f"{self.first or 'any'} to {self.last or 'any'}",
            "fixed_in": self.fixed_in,
            "summary": self.summary,
            "source": SOURCES.get(self.source, self.source),
        }


VERSION_ADVISORIES: tuple[VersionAdvisory, ...] = (
    VersionAdvisory(
        "client_upgrade_965", "9.1.965.4", "9.1.965.9", "9.1.965.12",
        "Manual client upgrades to these builds can leave the client service unable to start.",
        "adaptiva_client_upgrade_965",
    ),
    VersionAdvisory(
        "services_sensor_92", "9.2.0.0", "9.2.999.999", None,
        "New 9.2 client installs lack InventoryAgentNativeCode.dll; Services-sensor patches report Failed.",
        "adaptiva_services_sensor_92",
    ),
    VersionAdvisory(
        "sql_injection_968", None, "9.3.968.18", "9.3.968.19",
        "Release notes for 9.3.968.19 fix a SQL injection vulnerability and strongly recommend upgrading.",
        "tenable_release_notes_2025",
    ),
    VersionAdvisory(
        "hotfix_10_0_971_26", "10.0.971.0", "10.0.971.25", "10.0.971.26",
        "Hotfix 10.0.971.26 fixes server upgrade failures, client upgrade failures, Windows OS patching issues "
        "and other problems listed by Adaptiva.",
        "adaptiva_known_issues_10_0_971",
    ),
)

# --------------------------------------------------------------------------- #
# Where to get logs
# --------------------------------------------------------------------------- #

LOG_ACQUISITION: dict[str, str] = {
    "saas_server": "SaaS server logs are only available from the Admin Portal: gear icon > Logs > Download All "
                   "Server Logs (includes component and workflow logs). Register the downloaded .zip with "
                   "add_log_source.",
    "onprem_server": "On-prem server logs live in %ADAPTIVASERVER%\\logs (default C:\\Program Files\\Tenable\\"
                     "PatchServer\\logs); register the folder or a UNC path to it, or download them from the "
                     "Admin Portal > Logs page.",
    "client": "Client logs live in %ADAPTIVACLIENT%\\logs on the device (default C:\\Program Files\\Tenable\\"
              "PatchClient\\logs; /opt/tenable/patchclient/logs on Linux and macOS). Copy the folder, use "
              "collect/Collect-TPMLogs.ps1 for several devices, or request a log from the server (10.2.973.9 and "
              "later); such files are named like 13_adaptiva.log where 13 is the client ID.",
    "setup": "Installation logs are in %windir%\\AdaptivaSetupLogs\\Client\\AdaptivaClientSetup.log (and "
             "Server\\AdaptivaServerSetup.log on an on-prem server).",
}

TIMESTAMP_NOTE = (
    "Timestamps are shown exactly as written in the logs. TPM 10.2 SaaS server logs and Windows client logs "
    "were observed to be written in UTC; on-prem servers may use the server's local time."
)
