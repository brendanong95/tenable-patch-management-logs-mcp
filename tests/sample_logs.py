"""Synthetic TPM logs in the real line layouts, for the tests and the offline smoke test.

The layouts mirror real Tenable Patch Management 10.2.973.9 logs (a SaaS server bundle
and a Windows client). Every host name, ID, IP address and key here is invented.

The sample set, newest entry at ``END`` (2026-09-10 12:00):

* ``adaptiva-server/`` - a SaaS "Download All Server Logs" bundle (also zipped): feed
  checks that fail 12 times in the last 12 hours after one failure a day before, Tenable
  VM key validation failures, a CDN publication failure, SQL monitor noise, message
  retries to client 42, a rejected client install, three service starts in an hour.
* ``TPM-Logs-20260910/`` - a collector bundle with two Windows clients: WS-BAD07 (the
  documented Services-sensor issue, an MSI 1603 failure, a CBS error, low disk space,
  a dropped server connection, a failed client upgrade) and a healthy WS-GOOD01.
* ``13_adaptiva.log`` - a single client log requested from the server.
"""

from __future__ import annotations

import gzip
import io
import os
import tarfile
import zipfile
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

END = datetime(2026, 9, 10, 12, 0, 0)
WINDOW_START = END - timedelta(hours=24)

#: Fabricated key-shaped and token-shaped values (not real credentials) used to prove that
#: nothing resembling a secret survives into tool output.
PLANTED_KEY = "9f" * 32
PLANTED_TOKEN = "Zq8XvT3mLp7RkW2s"  # gitleaks:allow - fabricated
TENANT = "11111111-2222-4333-8444-555555555555"
FEED_THREAD = "AdaptivaTimer - FeedUpdate. ExecutingTask-FeedServer$FeedUpdateTimerTask"
REJECTED_IP = "10.20.30.40"


def ts(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%d %H:%M:%S,") + f"{moment.microsecond // 1000:03d}"


def line(moment: datetime, level: str, message: str, component: str, tid: int = 100,
         thread: str = "slm-transitions-2") -> str:
    return f"{ts(moment)} - {level} - {message} - {component} - TID={tid}, {thread}"


class LogSet:
    """Collects entries per file and writes them in time order."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.entries: dict[str, list[tuple[datetime, int, list[str]]]] = defaultdict(list)
        self.counter = 0

    def add(self, rel: str, moment: datetime, *lines: str) -> None:
        self.counter += 1
        self.entries[rel].append((moment, self.counter, list(lines)))

    def write(self) -> None:
        for rel, items in self.entries.items():
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            items.sort(key=lambda item: (item[0], item[1]))
            text = "\n".join(text for _, _, lines in items for text in lines) + "\n"
            if rel.endswith(".gz"):
                with gzip.open(path, "wt", encoding="utf-8", newline="\n") as fh:
                    fh.write(text)
            else:
                path.write_text(text, encoding="utf-8", newline="\n")
            stamp = items[-1][0].timestamp()
            os.utime(path, (stamp, stamp))


# --------------------------------------------------------------------------- #
# Server bundle
# --------------------------------------------------------------------------- #


def _feed_cycle(logs: LogSet, moment: datetime, *, fail: bool, rel: str, err_rel: str | None) -> None:
    logs.add(rel, moment, line(moment, "INFO", "[Periodic Feed Check] Started", "FeedServer", 1519, FEED_THREAD))
    constructed = moment + timedelta(milliseconds=100)
    logs.add(
        rel,
        constructed,
        f"{ts(constructed)} - INFO - [Periodic Feed Check] Package constructed.",
        "   === BEGIN PACKAGE CONTENTS ===",
        "      4 Adaptiva products installed",
        f"   === END PACKAGE CONTENTS === - FeedServer - TID=1519, {FEED_THREAD}",
    )
    done = moment + timedelta(milliseconds=300)
    if fail:
        failure = [
            line(done, "ERROR", "[Periodic Feed Check] An exception arose trying to retrieve new Feed instructions "
                               "from the Operations Manager!", "FeedServer", 1519, FEED_THREAD),
            "com.adaptiva.util.exceptions.AdaptivaException: Error Message = Could not complete REST API call., "
            "Error Code = 1 (0x1), Source Object = null",
            "\tat com.adaptiva.operations.client.rest.OperationsManagerEndPointClient.invokeWithErrorHandling"
            "(OperationsManagerEndPointClient.java:207)",
            "\tat com.adaptiva.feeds.server.FeedServer.launchFeedUpdateCycle(FeedServer.java:719)",
            "Caused by: java.io.IOException: Failed to make HTTP request",
            "\tat com.adaptiva.fw.net.http.HttpClient.execute(HttpClient.java:88)",
            "Caused by: org.apache.hc.core5.util.TimeoutValueException: Timeout deadline: 30000 MILLISECONDS, "
            "actual: 30012 MILLISECONDS",
            "\t... 7 more",
        ]
        logs.add(rel, done, *failure)
        if err_rel:
            logs.add(err_rel, done, *failure)
    else:
        logs.add(rel, done, line(done, "INFO", "[Periodic Feed Check] Feed instruction package received successfully.",
                                 "FeedServer", 1519, FEED_THREAD))
        logs.add(rel, done, line(done, "INFO", "[Periodic Feed Check] No new feeds found. Server is up to date.",
                                 "FeedServer", 1519, FEED_THREAD))
    logs.add(rel, done + timedelta(milliseconds=5),
             line(done + timedelta(milliseconds=5), "INFO", "[Periodic Feed Check] Finished", "FeedServer", 1519,
                  FEED_THREAD))


def build_server_bundle(root: Path) -> Path:
    """Write ``root/adaptiva-server`` and return that folder."""
    base = "adaptiva-server"
    logs = LogSet(root)
    current_start = datetime(2026, 9, 9, 0, 0, 0)

    # Older rotation, compressed: proves .gz reading and rotation naming.
    old = datetime(2026, 8, 25, 9, 0, 0)
    logs.add(f"{base}/adaptiva.2.log.gz", old, line(old, "INFO", "Current Version: 10.2.973.9", "Bootstrap", 3, "main"))
    logs.add(f"{base}/adaptiva.2.log.gz", old + timedelta(seconds=1),
             line(old + timedelta(seconds=1), "INFO", "Using SQL URL: jdbc:postgresql://db.example.internal:5432/tpm",
                  "SQLDataAccessManager", 172))

    # Baseline period (adaptiva.1.log, Feeds.1.log): quiet, one feed failure a day.
    day = datetime(2026, 9, 1, 0, 0, 0)
    while day < current_start:
        for hour in (1, 7, 13, 19):
            moment = day + timedelta(hours=hour)
            logs.add(f"{base}/adaptiva.1.log", moment,
                     line(moment, "INFO", "Currently processing policyId [100011] with policyVersion [1]",
                          "PolicyManager", 3340624, "Name=PartialMembershipEvaluationMultiThinThread_201, GroupID= 201"))
            logs.add(f"{base}/adaptiva.1.log", moment + timedelta(seconds=2),
                     line(moment + timedelta(seconds=2), "WARN",
                          "Could not find serverContentMetadataObject, while deleting receipts, no in-memory cleanup "
                          "required: Product_1000990008_Client$4$12", "ContentDownloadDataManager", 88))
        for hour in range(0, 24, 6):
            _feed_cycle(logs, day + timedelta(hours=hour, minutes=5), fail=(hour == 6),
                        rel=f"{base}/componentlogs/Feeds.1.log", err_rel=f"{base}/adaptiva.err")
        monitor = day + timedelta(hours=8, minutes=15)
        logs.add(
            f"{base}/sqlMonitor.log", monitor,
            line(monitor, "ERROR", "Exception occurred in executing SQL Query:EXEC [dbo].[prc_get_database_statistics]",
                 "ExtendedCacheInvalidator", 50),
            "com.adaptiva.util.exceptions.DataAccessException: Exception while performing SQL operation. "
            "- ErrorCode [0], ErrorString [UNSET], SQLState [42601]",
            "\tat com.adaptiva.fw.dao.sql.XStatement.executeQuery(XStatement.java:717)",
            'Caused by: org.postgresql.util.PSQLException: ERROR: syntax error at or near "EXEC"',
            "  Position: 1",
            "\tat org.postgresql.core.v3.QueryExecutorImpl.receiveErrorResponse(QueryExecutorImpl.java:2725)",
        )
        day += timedelta(days=1)

    # Current adaptiva.log: 2026-09-09 00:00 -> END.
    moment = current_start
    while moment <= END:
        logs.add(f"{base}/adaptiva.log", moment,
                 line(moment, "INFO", "Currently processing policyId [100011] with policyVersion [1]",
                      "PolicyManager", 3340624, "Name=PartialMembershipEvaluationMultiThinThread_201, GroupID= 201"))
        logs.add(f"{base}/adaptiva.log", moment + timedelta(seconds=3),
                 line(moment + timedelta(seconds=3), "WARN",
                      "Could not find serverContentMetadataObject, while deleting receipts, no in-memory cleanup "
                      "required: Product_1000990008_Client$4$13", "ContentDownloadDataManager", 88))
        moment += timedelta(hours=3)
    for index, hour in enumerate((8, 8.33, 8.66)):
        start = datetime(2026, 9, 10) + timedelta(hours=hour)
        logs.add(f"{base}/adaptiva.log", start, line(start, "INFO", "Current Version: 10.2.973.9", "Bootstrap", 3, "main"))
    jdbc = datetime(2026, 9, 10, 8, 0, 1)
    logs.add(f"{base}/adaptiva.log", jdbc,
             line(jdbc, "INFO", "Using SQL URL: jdbc:postgresql://db.example.internal:5432/tpm?password=Hunter2Hunter2",
                  "SQLDataAccessManager", 172))
    for count, hour in enumerate(range(1, 6), start=30):
        retry = datetime(2026, 9, 10, hour, 30, 0)
        logs.add(f"{base}/adaptiva.log", retry,
                 line(retry, "WARN", f"The message has been retried {count} times . Message is :Name of the message: "
                      "ContentDeletion, Sender ID: 0, Receiver ID: 42, Queue ID: 1, CORRELATION ID: 0, TTL: 2592000000",
                      "SendingThread", 212))
    token = datetime(2026, 9, 10, 6, 0, 0)
    logs.add(f"{base}/adaptiva.log", token,
             line(token, "INFO", f"Using old client token: {PLANTED_TOKEN}, for new client handshake",
                  "NewClientProvider", 3324372, "ConsumerTask: Sender Id = [1], Retry Level : 1"))
    rejected = datetime(2026, 9, 10, 6, 5, 0)
    rejection = line(rejected, "ERROR", f"All Client install authentication enabled, install attempted without auth "
                     f"information: /{REJECTED_IP}", "NewClientProvider", 3335436,
                     "ConsumerTask: Sender Id = [1], Retry Level : 1")
    logs.add(f"{base}/adaptiva.log", rejected, rejection)
    logs.add(f"{base}/adaptiva.err", rejected, rejection)
    dup = datetime(2026, 9, 10, 5, 20, 56)
    duplicate = [
        f"{ts(dup)} - ERROR - HHH000315: Exception executing batch [java.sql.BatchUpdateException: Batch entry 0 "
        "insert into SENSORACTIONEXECUTIONPOLICIES (NAME) values (('test')) was aborted: ERROR: duplicate key value "
        'violates unique constraint "uk_name"',
        "  Detail: Key (name)=(test) already exists.",
    ]
    logs.add(f"{base}/adaptiva.log", dup, *duplicate)
    logs.add(f"{base}/adaptiva.err", dup, *duplicate)

    # Current Feeds.log: healthy every 6h on 9 Sep, then hourly failures, recovering at 11:30.
    for hour in range(0, 24, 6):
        _feed_cycle(logs, datetime(2026, 9, 9) + timedelta(hours=hour, minutes=5), fail=False,
                    rel=f"{base}/componentlogs/Feeds.log", err_rel=None)
    for hour in range(0, 12):
        _feed_cycle(logs, datetime(2026, 9, 10) + timedelta(hours=hour, minutes=5), fail=True,
                    rel=f"{base}/componentlogs/Feeds.log", err_rel=f"{base}/adaptiva.err")
    _feed_cycle(logs, datetime(2026, 9, 10, 11, 30), fail=False, rel=f"{base}/componentlogs/Feeds.log", err_rel=None)

    # Tenable VM integration: no access settings, then keys rejected.
    vm = f"{base}/componentlogs/VulnerabilityManagement.log"
    for hour in range(0, 36, 2):
        run = datetime(2026, 9, 9) + timedelta(hours=hour, minutes=11)
        logs.add(vm, run, line(run, "INFO", "Performing update for tenable vulnerability data", "VmIntegrationManager", 61))
        logs.add(vm, run + timedelta(milliseconds=1),
                 line(run + timedelta(milliseconds=1), "WARN", "Tenable access settings have not been provided yet, "
                      "ignoring request for vulnerability data", "TenableClient", 61))
        logs.add(vm, run + timedelta(milliseconds=2),
                 line(run + timedelta(milliseconds=2), "INFO", "Processing 0 vulnerability detections that were "
                      "marked as NEW", "VmIntegrationCommonHelper", 61))
        logs.add(vm, run + timedelta(milliseconds=3),
                 line(run + timedelta(milliseconds=3), "INFO", "Update for tenable completed successfully. Marking last "
                      "update time at 2026-09-09T00:11:00.000Z", "VmIntegrationManager", 61))
    unauthorized = datetime(2026, 9, 9, 3, 0, 0)
    bad_keys = line(unauthorized, "ERROR", 'Tenable returned 401 UNAUTHORIZED for access key, it is invalid. Reason: '
                    '{"statusCode":401,"error":"Unauthorized","message":"Invalid credentials."}', "TenableClient", 1184,
                    "ForkJoinPool.commonPool-worker-1")
    logs.add(vm, unauthorized, bad_keys)
    logs.add(f"{base}/adaptiva.err", unauthorized, bad_keys)
    for minute in (0, 10, 20):
        attempt = datetime(2026, 9, 10, 9, minute, 0)
        logs.add(vm, attempt, line(attempt, "INFO", f"Testing validity of access settings with API key ID [{PLANTED_KEY}], "
                                   "verifying with Tenable Vulnerability Management (cloud)", "TenableClient", 1190))
        failed = attempt + timedelta(milliseconds=30)
        rejection_line = line(failed, "ERROR", f"Failed to validate settings with access key {PLANTED_KEY}, status code "
                              '401, body: {"error": "This scanner, agent, or API key token does not appear to be related '
                              'to any active containers on any sites."}', "TenableClient", 1190)
        logs.add(vm, failed, rejection_line)
        logs.add(f"{base}/adaptiva.err", failed, rejection_line)

    # CDN publication failure.
    publish = datetime(2026, 9, 10, 3, 0, 0)
    publication = [
        line(publish, "ERROR", "ContentException while trying to publish Content with id Policy_104117",
             "PolicyClientViewGenerator", 3120, "Workflow Thread [workflowId: 10798, instanceId: 2306, threadId: 4]"),
        "com.adaptiva.fw.net.contentSystem.ContentException: Error Message = Could not publish file "
        "[/opt/adaptiva/adaptiva-server/data//ContentLibrary/Policy_104117.12.content] to the cloud!, Error Code = 1 "
        "(0x1), Source Object = null",
        "\tat com.adaptiva.fw.net.contentSystem.CloudContentSupporter.publish(CloudContentSupporter.java:301)",
        "Caused by: java.net.SocketTimeoutException: Read timed out",
    ]
    logs.add(f"{base}/componentlogs/CdnService.log", publish, *publication)
    logs.add(f"{base}/adaptiva.err", publish, *publication)
    upload = datetime(2026, 9, 10, 2, 59, 0)
    logs.add(f"{base}/componentlogs/CdnService.log", upload,
             line(upload, "INFO", '[Bunny Storage APIs :: Upload "/opt/adaptiva/adaptiva-server/data//ContentLibrary/'
                  'Policy_104117.12.content"] Uploading...', "BunnyStorageApis", 3120))

    for index in range(10):
        noise = datetime(2026, 9, 9, 0, 13) + timedelta(hours=index * 3)
        logs.add(f"{base}/componentlogs/Http.log", noise,
                 line(noise, "WARN", "Shared client is not yet initialized, building and returning new client instead.",
                      "HttpClientManager", 172))
    cloud = datetime(2026, 9, 9, 0, 13, 52)
    logs.add(f"{base}/componentlogs/CloudInstanceManagement.log", cloud,
             line(cloud, "INFO", "Tenant settings refreshed", "CloudInstanceTenantApis", 190))
    block = datetime(2026, 9, 10, 1, 44, 27)
    logs.add(f"{base}/componentlogs/SQLUploader.log", block,
             "-----------------\tSTART(2026-09-10T01:44:27.942)\t---------------",
             "-----------------\tEND(2026-09-10T01:44:27.957)\t---------------")
    workflow = datetime(2026, 9, 10, 11, 33, 22)
    logs.add(
        f"{base}/workflowlogs/Policy Updated Workflow_10798_2306.log", workflow,
        "09-10-2026 11:33:22:8 : Prop: PolicyUpdate.WorkflowInstanceId, WHOLE NUMBER, Old: none, New: 2306",
        "09-10-2026 11:33:22:8 : Launching:Launched instance id [2306] Launched by[System] Launch data [{PatchingCycle=",
        "[",
        "1<[SinglePatchApproval, patchId:1021126111, desiredState:2, urgency:3]>",
        "] }]",
        "09-10-2026 11:33:22:9 : Exec: Starting: PolicyUpdate.Try1",
        "09-10-2026 11:33:23:1 : Exec: Ended: PolicyUpdate.Try1",
    )
    logs.write()
    return root / base


# --------------------------------------------------------------------------- #
# Client bundle
# --------------------------------------------------------------------------- #

SERVICES_SENSOR_ENTRY = [
    "2026-09-10 10:00:00,000 - INFO - Completion status for patch [1021126111], request [zpvzWCccTZKDdTfMrwrQsw] is "
    "[PatchDeploymentResult : patchID=[1021126111],, operation=1, softwareDeploymentOperationStatus=2, reasonCode=1, "
    "reasonMessage='com.adaptiva.expressionevaluator.EvaluatorException: Error Message = Failed to fully execute "
    "sensor with id[249000018], Error Code = 1 (0x1), Source Object = null",
    "\tat com.adaptiva.expressionevaluator.Evaluator.evaluate(Evaluator.java:120)",
    "Caused by: java.lang.UnsatisfiedLinkError: 'boolean com.adaptiva.inventory.inventoryagent."
    "WinNTServiceInventoryAgent.getServices(java.util.Vector)'",
    "', wuaRebootRequired=false]. - PatchingAdmin - TID=91, AdaptivaTimer - SoftwareDeploymentManager. "
    "ExecutingTask-SoftwareDeploymentManager$InstallationTimerTask",
]

SENSOR_WARNING = (
    'During evaluation of expression [Substring(SensorVolatile("RegistryValue","HKEY_LOCAL_MACHINE\\SOFTWARE\\'
    'Microsoft\\Windows\\CurrentVersion\\Appx\\AppxAllUserStore\\Applications"), "_x64")], 2 warnings were generated.'
)

MSI_LOG = "\r\n".join(
    [
        "=== Verbose logging started: 9/10/2026  10:01:00  Build type: SHIP UNICODE 5.00.10011.00  Calling process: "
        "C:\\WINDOWS\\system32\\msiexec.exe ===",
        "MSI (c) (1C:20) [10:01:00:100]: Resetting cached policy values",
        "Action start 10:01:01: InstallFinalize.",
        "CustomAction CA_RegisterService returned actual error code 1603 (note this may not be 100% accurate if "
        "translation happened inside sandbox)",
        "Action ended 10:01:02: InstallFinalize. Return value 3.",
        "MSI (s) (A4:B8) [10:01:02:200]: Product: Contoso App -- Installation failed.",
        "MSI (s) (A4:B8) [10:01:02:300]: Windows Installer installed the product. Product Name: Contoso App. Product "
        "Version: 2.4.1. Product Language: 1033. Manufacturer: Contoso Ltd. Installation success or error status: 1603.",
        "=== Verbose logging stopped: 9/10/2026  10:01:02 ===",
    ]
) + "\r\n"


def _client_common(logs: LogSet, base: str, *, healthy: bool) -> None:
    binding = datetime(2026, 9, 9, 0, 1, 0)
    logs.add(f"{base}/adaptiva.log", binding,
             line(binding, "INFO", f"Started with binding [https://{TENANT}.adaptiva.cloud/http2].",
                  "HttpTransportV2Client", 4, "slm-transitions-3"))
    moment = datetime(2026, 9, 9, 0, 10, 0)
    while moment <= END:
        logs.add(f"{base}/adaptiva.log", moment,
                 line(moment, "INFO", "HTTP connection disconnected 1 times.", "HttpTransportV2Client", 227420,
                      "SystemLifetimeManagerPooledTimer-112"))
        moment += timedelta(minutes=60)
    warning = datetime(2026, 9, 10, 11, 36, 50)
    logs.add(f"{base}/adaptiva.log", warning,
             line(warning, "WARN", SENSOR_WARNING, "SensorActionExpressionEvaluator", 59006, "multi-pass-scanner-9375"))
    if healthy:
        ok = datetime(2026, 9, 10, 10, 0, 0)
        logs.add(f"{base}/componentlogs/PatchingAdmin.log", ok,
                 line(ok, "INFO", "Completion status for patch [1021126111], request [kQ2wAbCdEfGhIjKlMnOp] is "
                      "[PatchDeploymentResult : patchID=[1021126111],, operation=1, softwareDeploymentOperationStatus=1, "
                      "reasonCode=0, reasonMessage='', wuaRebootRequired=false]", "PatchingAdmin", 91))


def build_client_bundle(root: Path) -> Path:
    """Write ``root/TPM-Logs-20260910`` (collector layout) and return it."""
    bundle = "TPM-Logs-20260910"
    logs = LogSet(root)
    bad = f"{bundle}/WS-BAD07/PatchClient/logs"
    good = f"{bundle}/WS-GOOD01/PatchClient/logs"
    _client_common(logs, bad, healthy=False)
    _client_common(logs, good, healthy=True)

    dropped = datetime(2026, 9, 10, 9, 15, 0)
    logs.add(
        f"{bad}/adaptiva.log", dropped,
        line(dropped, "ERROR", "Unable to send: ", "HttpTransportV2Client", 236, "ApacheHttpClient-v2"),
        "org.apache.hc.core5.http.ConnectionClosedException: Connection is closed",
        "\tat org.apache.hc.core5.http2.impl.nio.FrameInputBuffer.read(FrameInputBuffer.java:181)",
    )
    sensor = datetime(2026, 9, 10, 10, 0, 0)
    for rel in (f"{bad}/componentlogs/PatchingAdmin.log", f"{bad}/componentlogs/SoftwareDeploymentManager.log",
                f"{bad}/adaptiva.err"):
        logs.add(rel, sensor, *SERVICES_SENSOR_ENTRY)
    install = datetime(2026, 9, 10, 10, 1, 5)
    logs.add(f"{bad}/componentlogs/_SDMErrors.log", install,
             line(install, "ERROR", "Installation of patch [1021126111] for product [Contoso App] failed with exit "
                  "code [1603]", "SoftwareInstaller", 77, "SoftwareInstaller-3"))
    cbs = datetime(2026, 9, 10, 10, 30, 0)
    logs.add(f"{bad}/componentlogs/WindowsPatching.log", cbs,
             line(cbs, "ERROR", "Windows update KB5030211 failed to install, result code 0x800F0922", "WindowsPatching",
                  78, "WindowsUpdateInstaller-1"))
    space = datetime(2026, 9, 10, 7, 0, 0)
    logs.add(f"{bad}/componentlogs/ContentCache.log", space,
             line(space, "INFO", "Drive [C] is having actualFreeSpace Including Progress [21474836480]", "ContentCache",
                  12, "ContentCacheTimer"))
    scan = datetime(2026, 9, 10, 7, 5, 0)
    logs.add(f"{bad}/componentlogs/PatchingAdmin.log", scan,
             line(scan, "INFO", "Product [Windows 11 24H2 Feature Update] Scanned status [NOT INSTALLED]",
                  "PatchingAdmin", 91))
    upgrade = datetime(2026, 9, 9, 7, 0, 0)
    logs.add(
        f"{bundle}/WS-BAD07/AdaptivaSetupLogs/Client/AdaptivaClientSetup.log", upgrade,
        f"{ts(upgrade)} - ERROR - Virtual Mode upgrade failed with an error: com.adaptiva.util.exceptions."
        "AdaptivaException: Error Message = Failed to delete objects with className: [class com.adaptiva.patching."
        "client.status.PatchDeploymentResultStore] and whereClause: [null], Error Code = 1 (0x1), Source Object = null",
        "        at com.adaptiva.fw.simpleobjectmanager.SimpleObjectManager.deleteObjectsByQuery"
        "(SimpleObjectManager.java:605)",
    )
    logs.write()

    msi = root / bad / "msiLogs" / "1021126111_ab12cd34.log"
    msi.parent.mkdir(parents=True, exist_ok=True)
    msi.write_bytes(b"\xff\xfe" + MSI_LOG.encode("utf-16-le"))
    stamp = datetime(2026, 9, 10, 10, 1, 2).timestamp()
    os.utime(msi, (stamp, stamp))
    return root / bundle


def build_single_client_log(root: Path) -> Path:
    """A client log requested from the server: ``13_adaptiva.log`` covering the last 18 hours."""
    logs = LogSet(root)
    moment = END - timedelta(hours=18)
    while moment <= END:
        logs.add("13_adaptiva.log", moment,
                 line(moment, "INFO", "Folder C:\\Program Files\\Tenable\\PatchClient\\data\\transactionLogs\\\\com."
                      "adaptiva.patching.client.policy.PatchingPolicyClient successfully deleted.", "TransactionLog", 58,
                      "PatchingPolicyClient-Tasks-1"))
        moment += timedelta(hours=2)
    closed = END - timedelta(hours=1)
    logs.add("13_adaptiva.log", closed,
             line(closed, "ERROR", "Failed to check alive status of server: ", "HttpTransportV2Client", 236,
                  "ApacheHttpClient-v2"),
             "org.apache.hc.core5.http.ConnectionClosedException: Connection is closed")
    logs.write()
    return root / "13_adaptiva.log"


# --------------------------------------------------------------------------- #
# Archives
# --------------------------------------------------------------------------- #


def zip_folder(folder: Path, destination: Path) -> Path:
    """Zip ``folder`` so the archive's top level is the folder itself."""
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(folder.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(folder.parent).as_posix())
    return destination


def tar_folder(folder: Path, destination: Path) -> Path:
    with tarfile.open(destination, "w:gz") as tf:
        tf.add(folder, arcname=folder.name)
    return destination


def malicious_zip(destination: Path) -> Path:
    """A zip with path-traversal entries next to one legitimate log."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("../../escaped.log", "should never be written\n")
        zf.writestr("/absolute.log", "should never be written\n")
        zf.writestr("C:/drive.log", "should never be written\n")
        zf.writestr("logs/adaptiva.log", line(END, "INFO", "legit entry", "Bootstrap") + "\n")
    destination.write_bytes(buffer.getvalue())
    return destination


def build_sample_tree(root: Path) -> dict[str, Path]:
    """Everything above, plus zipped and tarred copies. Returns the interesting paths."""
    root.mkdir(parents=True, exist_ok=True)
    server_dir = build_server_bundle(root / "server")
    clients_dir = build_client_bundle(root / "clients")
    client13 = build_single_client_log(root / "single")
    server_zip = zip_folder(server_dir, root / "logs.zip")
    clients_tar = tar_folder(clients_dir, root / "clients.tar.gz")
    return {
        "root": root,
        "server_dir": server_dir,
        "server_zip": server_zip,
        "clients_dir": clients_dir,
        "clients_tar": clients_tar,
        "client13_file": client13,
    }
