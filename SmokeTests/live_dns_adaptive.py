#!/usr/bin/env python3
"""Guarded production DNS success, latency preference and failed TLS paths.

All peers bind literal 127.0.0.1. Healthy peers use an ephemeral, private CA
which the explicit CLI fixture validates per connection, never installs.
Ordinary questions must never reach the traditional UDP sink, under either
protection setting. Production-carrier cases add a literal-only CONNECT relay
without inspecting TLS. No GUI, Helper, public DNS or user configuration is used.
"""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import select
import selectors
import socket
import socketserver
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import ExitStack, contextmanager


SOURCE_SCOPE_PREFLIGHT_ACK = b"HAJIMI-DNS-PREFLIGHT/1\r\n"
SOURCE_SCOPE_TIMING_MARKER = "DNS-SOURCE-SCOPE-TIMING "
SOURCE_SCOPE_TIMING_MAXIMUM_BYTES = 16_384
MULTI_UPSTREAM_SCENARIOS = {"multi-upstream-burst", "multi-upstream-connect-failure-burst"}
BIND_PREFIX = b"HAJIMI-TLS-BIND/1 "
BIND_ACK_PREFIX = b"HAJIMI-TLS-ACK/1 "
BIND_SUFFIX_BYTES = 44  # UUID(36), space, provider, space, ordinal(3), CRLF.
CARRIER_PROOF_COLUMNS = ("nonce", "ordinal", "provider", "bindingACK", "nativeTLSStarted", "explicitCancel",
                         "nativeResultAt", "handoffAt", "nativeResult", "nativeCase", "NSErrorDomain", "NSErrorCode",
                         "classification", "httpQueries", "firstObserverDeny", "observerAuthenticationCount",
                         "preludeFailure", "boundTypedAbort")
NONCE_PATTERN = re.compile(r"[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}")
IDENTITY_SCENARIO = "production-identity-failure"
IDENTITY_MARKER = "DNS-ADAPTIVE-IDENTITY "
CLIENT_HELLO_PREFIX_BYTES = 43
IDENTITY_ERROR_DOMAIN = "NSOSStatusErrorDomain"
IDENTITY_HOSTNAME_MISMATCH = -67602
IDENTITY_TRUST_KEYS = ("ownerToken", "startCount", "returnCount", "callbackCount", "startedAt", "returnedAt", "callbackAt",
                       "returnStatus", "trusted", "hasError", "errorIsCFError", "errorDomain", "errorCode", "certificateCount",
                       "leafSHA256", "evaluatedAnchorSHA256", "fixtureAnchorSHA256")
IDENTITY_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


class Trace:
    def __init__(self, maximum_events: int = 256) -> None:
        self.lock = threading.Lock()
        self.started = time.monotonic()
        self.events: list[dict] = []
        self.dropped_events = 0
        self.maximum_events = maximum_events
        self.providers: list[dict] = []
        self.hellos: list[str] = []
        self.tls_peers: list[tuple[str, tuple[str, int]]] = []
        self.queries: list[tuple[str, str]] = []
        self.query_peers: list[tuple[str, str, tuple[str, int]]] = []
        self.query_details: list[tuple[str, str, int, tuple[str, int]]] = []
        self.response_details: list[tuple[str, str, int, tuple[str, int]]] = []
        self.tls_ready: list[tuple[str, tuple[str, int]]] = []
        self.tls_closed: list[tuple[str, tuple[str, int]]] = []
        self.preflight_acknowledgements: list[tuple[str, tuple[str, int], str]] = []
        self.source_scope_timing: dict | None = None
        self.multi_upstream_timing: dict | None = None
        self.multi_upstream_client_answers: list | None = None
        self.carrier_bindings: list[dict] = []
        self.handshake_eofs: list[dict] = []
        self.carrier_proof: dict | None = None
        self.functional_witness: dict | None = None
        self.identity_observation = False
        self.identity_witness: dict | None = None
        self.identity_ssl_errors: list[dict] = []
        self.tls_active = self.tls_peak = 0
        self.wire_active = self.wire_peak = 0
        self.scope_checkpoints: list[dict] = []
        self.rejected: list[str] = []
        self.connects: list[tuple[str, int]] = []
        self.connect_failures: list[tuple[str, int, int]] = []
        self.proxy_peers: list[str] = []
        self.proxy_connections: list[dict] = []
        self.approved_proxy_endpoint: tuple[str, int] | None = None
        self.proxy_handlers_active: int | None = None
        self.proxy_rejected: list[str] = []
        self.plaintext = 0
        self.errors: list[str] = []

    def event_locked(self, kind: str, **fields) -> None:
        """Caller holds lock; diagnostics do not alter any wire expectations."""
        if len(self.events) >= self.maximum_events:
            self.dropped_events += 1
            return
        self.events.append({"seconds": round(time.monotonic() - self.started, 6),
                            "event": kind, **fields})

    def snapshot(self) -> dict:
        with self.lock:
            return {"clock": "monotonic seconds from case setup; cli-start marks launch",
                    "elapsedSeconds": round(time.monotonic() - self.started, 6),
                    "providers": list(self.providers), "tls": list(self.hellos),
                    "tlsPeers": list(self.tls_peers),
                    "queries": list(self.queries), "queryPeers": list(self.query_peers),
                    "queryDetails": list(self.query_details), "responseDetails": list(self.response_details),
                    "tlsReady": list(self.tls_ready), "tlsClosed": list(self.tls_closed),
                    "preflightACKs": list(self.preflight_acknowledgements),
                    "sourceScopeTiming": self.source_scope_timing,
                    "multiUpstreamTiming": self.multi_upstream_timing,
                    "multiUpstreamClientAnswers": self.multi_upstream_client_answers,
                    "carrierBindings": deepcopy(self.carrier_bindings), "handshakeEOFs": deepcopy(self.handshake_eofs),
                    "carrierProof": deepcopy(self.carrier_proof),
                    "functionalWitness": deepcopy(self.functional_witness),
                    "identityObservation": self.identity_observation,
                    "identityWitness": deepcopy(self.identity_witness),
                    "identitySSLErrors": deepcopy(self.identity_ssl_errors),
                    "tlsHandlersActive": self.tls_active, "tlsHandlersPeak": self.tls_peak,
                    "wireActive": self.wire_active, "wirePeak": self.wire_peak,
                    "scopeCheckpoints": list(self.scope_checkpoints),
                    "identityRejected": list(self.rejected), "connects": list(self.connects),
                    "connectFailures": list(self.connect_failures),
                    "proxyPeers": list(self.proxy_peers), "proxyRejected": list(self.proxy_rejected),
                    "proxyConnections": deepcopy(self.proxy_connections),
                    "approvedProxyEndpoint": self.approved_proxy_endpoint,
                    "proxyHandlersActive": self.proxy_handlers_active,
                    "plaintext": self.plaintext, "errors": list(self.errors),
                    "events": list(self.events), "droppedEvents": self.dropped_events}


@contextmanager
def failure_trace(trace: Trace, protection: bool, scenario: str):
    try:
        yield
    except (AssertionError, OSError, subprocess.TimeoutExpired) as error:
        details = trace.snapshot()
        details.update({"protection": protection, "scenario": scenario,
                        "exceptionType": type(error).__name__, "exception": str(error)[:4096]})
        print("ADAPTIVE_FAILURE_TRACE " + json.dumps(details, sort_keys=True), file=sys.stderr, flush=True)
        raise


def require_completed_cli(result: subprocess.CompletedProcess) -> str:
    details = (result.stdout + "\n" + result.stderr).strip()
    if result.returncode != 0:
        raise AssertionError(f"Adaptive CLI exited {result.returncode}: {details}")
    if "DNS adaptive loopback checks passed" not in result.stdout:
        raise AssertionError("Binary did not execute the guarded adaptive CLI")
    return details


def capture_source_scope_timing(details: str, trace: Trace, *, multi_upstream: bool = False) -> None:
    """Retain bounded diagnostic JSON even when an earlier CLI assertion fails.

    This does not authorize wire traffic, alter an oracle or replace the
    original failure. Never echo malformed/unbounded input into the trace.
    """
    marker = "DNS-MULTI-UPSTREAM-TIMING " if multi_upstream else SOURCE_SCOPE_TIMING_MARKER
    rows = [line[len(marker):] for line in details.splitlines() if line.startswith(marker)]
    failure = None
    value = None
    if len(rows) != 1:
        failure = "missing" if not rows else "duplicate"
    elif len(rows[0].encode("utf-8")) > SOURCE_SCOPE_TIMING_MAXIMUM_BYTES:
        failure = "too-large"
    else:
        try:
            value = json.loads(rows[0])
        except (ValueError, UnicodeError):
            failure = "invalid-json"
        if failure is None and (not isinstance(value, dict) or type(value.get("formatVersion")) is not int
                                or value.get("formatVersion") != 1 or value.get("fixtureOnly") is not True):
            failure = "invalid-format"
    with trace.lock:
        captured = {"available": False, "observationError": failure} if failure else value
        if multi_upstream:
            trace.multi_upstream_timing = captured
        else:
            trace.source_scope_timing = captured


def validate_wire_trace(observed: dict, base_scenario: str, production: bool,
                        endpoint_ports: dict[str, int]) -> int:
    """Only success may add <=2 approved, HTTP-empty second-provider carriers.

    Authenticated answers/RCODE/cache ownership remain the unchanged Core CLI's
    responsibility, which must complete successfully before this is called.
    Negative TLS/identity scenarios retain their original exact wire oracle.
    """
    if base_scenario == "source-scope-burst":
        validate_source_scope_wire_trace(observed, production, endpoint_ports)
        return 0
    if base_scenario in MULTI_UPSTREAM_SCENARIOS:
        validate_multi_upstream_wire_trace(observed, production, endpoint_ports, base_scenario)
        return 0
    if base_scenario == "success" and observed.get("functionalWitness") is not None:
        return validate_functional_success_trace(observed, production, endpoint_ports)
    hellos = list(observed["tls"])
    queries = [tuple(item) for item in observed["queries"]]
    rejected = list(observed["identityRejected"])
    unproved_errors = observed["errors"]
    if base_scenario == "identity-failure" and production and observed.get("identityObservation") is True:
        rejected, proved_identity_errors = validate_identity_evidence(observed, endpoint_ports)
        unproved_errors = set(range(len(observed["errors"]))) - proved_identity_errors
    connects = [tuple(item) for item in observed["connects"]]
    proxy_peers = list(observed["proxyPeers"])
    if base_scenario == "failure":
        expected_hellos, expected_queries, expected_rejected = ["first", "second", "first", "second"], [], []
    elif base_scenario == "success":
        expected_hellos, expected_rejected = ["first", "second", "first"], []
        expected_queries = [("first", "adaptive.cold.example.test"), ("second", "adaptive.discover.example.test"),
                            ("second", "adaptive.preferred.example.test"), ("first", "adaptive.cold.example.test")]
    elif base_scenario == "identity-failure":
        expected_hellos, expected_rejected = ["first", "second", "first", "second"], ["first", "first"]
        expected_queries = [("second", "adaptive.identity.example.test"), ("second", "adaptive.identity-next.example.test"),
                            ("second", "adaptive.identity.example.test")]
    else:
        raise AssertionError("Unknown adaptive wire-oracle scenario")
    if (queries != expected_queries or rejected != expected_rejected or observed["proxyRejected"]
            or observed["plaintext"] != 0 or unproved_errors):
        raise AssertionError(f"Unexpected wire trace: TLS={hellos}, questions={queries}, SAN-rejected={rejected}, "
                             f"CONNECT={connects}, proxy-peers={proxy_peers}, "
                             f"proxy-rejected={observed['proxyRejected']}, "
                             f"traditional={observed['plaintext']}, errors={observed['errors']}")
    if base_scenario != "success":
        expected_connects = [("127.0.0.1", endpoint_ports[label]) for label in expected_hellos] if production else []
        if (hellos != expected_hellos or connects != expected_connects
                or proxy_peers != ["127.0.0.1"] * len(expected_connects)):
            raise AssertionError("Negative adaptive scenario changed its exact TLS/CONNECT sequence")
        return 0

    tls_peers = [(label, tuple(peer)) for label, peer in observed["tlsPeers"]]
    query_peers = [(label, name, tuple(peer)) for label, name, peer in observed["queryPeers"]]
    if (len(query_peers) != 4 or [(label, name) for label, name, _ in query_peers] != expected_queries
            or query_peers[1][2] != query_peers[2][2] or query_peers[0][2] == query_peers[3][2]):
        raise AssertionError("TLS query ownership/reuse or post-flush fresh dial was not observed")
    if ([label for label, _ in tls_peers] != hellos or not 3 <= len(tls_peers) <= 5
            or len(set(tls_peers)) != len(tls_peers)
            or any(label not in {"first", "second"} or len(peer) != 2 or peer[0] != "127.0.0.1"
                   or not isinstance(peer[1], int) or not 0 < peer[1] <= 65535 for label, peer in tls_peers)):
        raise AssertionError("TLS carriers exceeded their bounded literal-loopback provider scope")
    queried = {(label, peer) for label, _, peer in query_peers}
    if len(queried) != 3 or not queried.issubset(set(tls_peers)):
        raise AssertionError("HTTP DNS query did not belong to its observed approved TLS carrier")
    speculative = [(label, peer) for label, peer in tls_peers if (label, peer) not in queried]
    if len(speculative) > 2 or any(label != "second" for label, _ in speculative):
        raise AssertionError("Only two HTTP-empty approved second-provider speculative TLS carriers are permitted")
    # CONNECT acceptance and TLS worker startup can be scheduled in different
    # orders. Counts must nevertheless correspond exactly at each approved port.
    expected_connects = [("127.0.0.1", endpoint_ports[label]) for label in hellos] if production else []
    if (Counter(connects) != Counter(expected_connects)
            or proxy_peers != ["127.0.0.1"] * len(expected_connects)):
        raise AssertionError("CONNECT carriers did not match the exact approved TLS endpoint counts")
    return len(speculative)


def client_hello_random(prefix: bytes) -> str:
    """Parse only the fixed existing TLS prefix; never consume/rewrite a stream."""
    if (len(prefix) != CLIENT_HELLO_PREFIX_BYTES or prefix[0] != 22 or prefix[1] != 3
            or prefix[2] not in {1, 2, 3} or prefix[5] != 1 or prefix[9] != 3 or prefix[10] not in {1, 2, 3}):
        raise AssertionError("Missing or nonstandard first ClientHello prefix")
    record_length = int.from_bytes(prefix[3:5], "big")
    hello_length = int.from_bytes(prefix[6:9], "big")
    if not 38 <= record_length <= 18_432 or hello_length < 34 or hello_length + 4 > record_length:
        raise AssertionError("Short/cross-record ClientHello cannot bind an identity proof")
    return prefix[11:43].hex()


def validate_identity_evidence(observed: dict, endpoint_ports: dict[str, int]) -> tuple[list[str], set[int]]:
    """Joint original SecTrust + typed TLS/random/peer proof, identity only.

    A generic NWError.tls(-9808) alone is never a hostname-denial proof. The
    actual SDK callback must supply its original hostname CFError, evaluated
    leaf/anchor and this same physical token before the original native deny.
    """
    proof = observed.get("identityWitness")
    integer_fields = ("formatVersion", "recordLimit", "prefixBytesLimit", "rawReady", "tlsReady", "tlsFailures",
                      "pendingCallbacks", "droppedRecords", "invalidObservations", "nativeWriteFailures")
    if (not isinstance(proof, dict) or len(json.dumps(proof, separators=(",", ":"), ensure_ascii=False).encode()) > 16_384
            or any(type(proof.get(key)) is not int for key in integer_fields)
            or proof.get("formatVersion") != 1 or proof.get("fixtureOnly") is not True
            or proof.get("scenario") != IDENTITY_SCENARIO or proof.get("successAssertionsCompleted") is not True
            or proof.get("binding") != "passive existing TLS ClientHello.random"
            or proof.get("recordLimit") != 128 or proof.get("prefixBytesLimit") != CLIENT_HELLO_PREFIX_BYTES
            or proof.get("rawReady") != 4 or proof.get("tlsReady") != 2 or proof.get("tlsFailures") != 2
            or any(proof.get(key) != 0 for key in ("pendingCallbacks", "droppedRecords", "invalidObservations", "nativeWriteFailures"))
            or proof.get("approvedProviderPorts") != [endpoint_ports["first"], endpoint_ports["second"]]):
        raise AssertionError("Identity witness omitted a native owner/result or changed its fixed authority/bounds")
    proxy = proof.get("approvedProxy")
    if (not isinstance(proxy, dict) or proxy.get("name") != "LoopbackHTTP" or proxy.get("host") != "127.0.0.1"
            or type(proxy.get("port")) is not int or tuple(observed.get("approvedProxyEndpoint") or ()) != ("127.0.0.1", proxy["port"])):
        raise AssertionError("Identity proof did not use the exact admitted CONNECT node")
    expected_answers = [[0x7301, 0, "203.0.113.81"], [0x7302, 0, "203.0.113.81"],
                        [0x7303, 5, None], [0x7304, 0, "203.0.113.81"]]
    if proof.get("answers") != expected_answers:
        raise AssertionError("Identity proof lost response IDs, approved winner, REJECT or fresh-epoch answer")
    providers = observed.get("providers", [])
    if (not isinstance(providers, list) or len(providers) != 2 or any(not isinstance(item, dict) for item in providers)
            or [item.get("provider") for item in providers] != ["first", "second"]
            or [item.get("authority") for item in providers] != [f"127.0.0.1:{endpoint_ports[label]}" for label in ("first", "second")]
            or providers[0].get("identityFailure") is not True or providers[1].get("identityFailure") is not False
            or any(not isinstance(item.get(key), str) or IDENTITY_SHA256_PATTERN.fullmatch(item[key]) is None
                   for item in providers for key in ("loadedLeafSHA256", "fixtureAnchorSHA256"))
            or providers[0]["loadedLeafSHA256"] == providers[1]["loadedLeafSHA256"]
            or providers[0]["fixtureAnchorSHA256"] != providers[1]["fixtureAnchorSHA256"]
            or any(item["loadedLeafSHA256"] == item["fixtureAnchorSHA256"] for item in providers)):
        raise AssertionError("Identity proof changed the two original certificate/provider fixtures")
    records, relays = proof.get("records"), observed.get("proxyConnections")
    peers = {(label, tuple(peer)) for label, peer in observed["tlsPeers"]}
    ready = {(label, tuple(peer)) for label, peer in observed["tlsReady"]}
    if (not isinstance(records, list) or len(records) != 4 or not isinstance(relays, list) or len(relays) != 4
            or len(peers) != 4 or {(label, tuple(peer)) for label, peer in observed["tlsClosed"]} != peers
            or any(observed.get(key) != 0 for key in ("tlsHandlersActive", "wireActive", "proxyHandlersActive"))):
        raise AssertionError("Identity evidence omitted an actual socket or physical teardown")

    def time_value(value, *, optional=False):
        if optional and value is None:
            return None
        if type(value) not in {int, float} or not math.isfinite(value) or value < 0:
            raise AssertionError("Identity ordering is not actual finite monotonic metadata")
        return value

    def certificate(error):
        # Necessary native evidence, not sufficient identity authorization.
        # Every call below follows the mandatory same-owner SDK/DER gate.
        if (not isinstance(error, dict) or error.get("actualNWErrorTLS") is not True
                or error.get("swiftType") != "Network.NWError" or error.get("NWErrorKind") != "tls"
                or type(error.get("NWErrorCode")) is not int or error["NWErrorCode"] not in {-9808, -9807, -9843}
                or error.get("classification") != "authentication" or "NativeOutboundErrorCase" in error):
            raise AssertionError("No actual typed NWError.tls certificate denial; NSError/text/unknown cannot substitute")
        return error["NWErrorCode"]

    by_random = {}; tokens = set(); by_peer = {}; denied = set()
    for index, record in enumerate(records):
        if (not isinstance(record, dict) or record.get("ordinal") != index or type(record.get("ordinal")) is not int
                or record.get("provider") != index % 2 or type(record.get("provider")) is not int
                or not isinstance(record.get("token"), str) or NONCE_PATTERN.fullmatch(record["token"]) is None
                or record["token"] in tokens or record.get("port") != endpoint_ports["first" if index % 2 == 0 else "second"]
                or not isinstance(record.get("clientHelloPrefixHex"), str) or re.fullmatch(r"[0-9a-f]{86}", record["clientHelloPrefixHex"]) is None
                or record.get("clientHelloPrefixBytes") != 43 or record.get("prefixWrittenBytes") != 43
                or any(type(record.get(key)) is not int for key in ("clientHelloPrefixBytes", "prefixWrittenBytes", "prefixCallbacks",
                                                                  "prefixWriteFailures", "nativeResultCount", "rawCancelCount"))
                or type(record.get("prefixWrites")) is not int or not 1 <= record["prefixWrites"] <= 43
                or record.get("prefixCallbacks") != record["prefixWrites"] or record.get("prefixWriteFailures") != 0
                or record.get("prefixWriteError") is not None or record.get("nativeResultCount") != 1
                or type(record.get("httpSends")) is not int or record["httpSends"] < 0
                or type(record.get("applicationBytes")) is not int or record["applicationBytes"] < 0):
            raise AssertionError("Identity owner/prefix/write receipt/HTTP ownership is incomplete or ambiguous")
        tokens.add(record["token"])
        random = client_hello_random(bytes.fromhex(record["clientHelloPrefixHex"]))
        if random in by_random:
            raise AssertionError("Repeated ClientHello.random cannot identify a unique real carrier")
        raw, started, result, handoff = [time_value(record.get(key)) for key in ("rawReadyAt", "nativeTLSStartedAt", "nativeResultAt", "handoffAt")]
        first_write, last_write = [time_value(record.get(key)) for key in ("firstPrefixCallbackAt", "lastPrefixCallbackAt")]
        if not raw <= started <= result <= handoff or not started <= first_write <= last_write:
            raise AssertionError("Identity proof fabricated native phase or real write callback ordering")
        trust = record.get("trustEvaluation"); provider = providers[index % 2]
        if (not isinstance(trust, dict) or any(key not in trust for key in IDENTITY_TRUST_KEYS)
                or trust.get("ownerToken") != record["token"]
                or any(type(trust.get(key)) is not int or trust[key] != 1 for key in ("startCount", "returnCount", "callbackCount"))
                or type(trust.get("returnStatus")) is not int or trust["returnStatus"] != 0
                or any(type(trust.get(key)) is not bool for key in ("trusted", "hasError", "errorIsCFError"))
                or (trust["errorDomain"] is not None and (not isinstance(trust["errorDomain"], str)
                                                         or len(trust["errorDomain"].encode()) > 256))
                or (trust["errorCode"] is not None and type(trust["errorCode"]) is not int)
                or type(trust.get("certificateCount")) is not int or not 2 <= trust["certificateCount"] <= 16
                or trust.get("leafSHA256") != provider["loadedLeafSHA256"]
                or trust.get("evaluatedAnchorSHA256") != provider["fixtureAnchorSHA256"]
                or trust.get("fixtureAnchorSHA256") != provider["fixtureAnchorSHA256"]):
            raise AssertionError("No unique same-owner original SDK receipt/actual loaded leaf and anchor proof")
        trust_started, trust_returned, trust_callback = [time_value(trust[key]) for key in ("startedAt", "returnedAt", "callbackAt")]
        # Both events follow the real call start, but either may come first.
        # Never reject an actual inline callback by assuming return < callback.
        if (not started <= trust_started <= trust_returned or not trust_started <= trust_callback <= result):
            raise AssertionError("Original SecTrust call/return/callback ordering is impossible for this native owner")
        for key in ("rawCancelAt", "ownCancelAt", "rawTerminalAt", "certificateObserverAt", "firstObserverAt", "lastObserverAt", "firstUnknownObserverAt"):
            if key not in record:
                raise AssertionError("Identity witness omitted an ordering field; missing is not an observed null")
            time_value(record.get(key), optional=True)
        if (record["rawCancelCount"] < 0 or ((record.get("rawCancelAt") is None) != (record["rawCancelCount"] == 0))):
            raise AssertionError("Raw cancellation timestamp is not its actual caller receipt")
        if index % 2 == 0:
            if (trust["trusted"] is not False or trust["hasError"] is not True or trust["errorIsCFError"] is not True
                    or trust["errorDomain"] != IDENTITY_ERROR_DOMAIN
                    or type(trust["errorCode"]) is not int or trust["errorCode"] != IDENTITY_HOSTNAME_MISMATCH):
                raise AssertionError("No actual SecTrust false callback with its original hostname-mismatch CFError")
            code = certificate(record.get("certificateError"))
            if (record.get("nativeResult") != "failure" or certificate(record.get("nativeError")) != code
                    or record.get("httpSends") != 0 or record.get("applicationBytes") != 0
                    or type(record.get("observerCount")) is not int or record["observerCount"] < 1):
                raise AssertionError("Wrong-SAN carrier succeeded, sent application bytes or returned an unknown native result")
            auth = time_value(record.get("certificateObserverAt")); close = time_value(record.get("rawCancelAt"))
            if (time_value(record.get("firstObserverAt")) != auth or certificate(record.get("firstObserverError")) != code):
                raise AssertionError("A later certificate denial cannot replace the original first typed authentication error")
            if (not trust_callback <= auth < close <= result or (record.get("ownCancelAt") is not None and not auth < record["ownCancelAt"])
                    or (record.get("rawTerminalAt") is not None and not auth < record["rawTerminalAt"])
                    or (record.get("firstUnknownObserverAt") is not None and not close < record["firstUnknownObserverAt"])):
                raise AssertionError("Actual certificate rejection did not precede raw close/own cutoff/unknown terminal")
        elif (record.get("nativeResult") != "success" or record.get("nativeError") is not None
              or record.get("certificateError") is not None or record.get("certificateObserverAt") is not None
              or trust["trusted"] is not True or trust["hasError"] is not False or trust["errorIsCFError"] is not False
              or trust["errorDomain"] is not None or trust["errorCode"] is not None
              or record["httpSends"] != (2 if index == 1 else 1) or record["applicationBytes"] == 0):
            raise AssertionError("Healthy identity fallback did not use its exact authenticated native carrier")
        by_random[random] = record
    for relay_record in relays:
        if (relay_record.get("identityCapture") is not True or relay_record.get("connectHeaderComplete") is not True
                or relay_record.get("upstreamOpened") is not True or relay_record.get("closedSeconds") is None
                or tuple(relay_record.get("proxyEndpoint", [])) != ("127.0.0.1", proxy["port"])
                or tuple(relay_record.get("peer", []))[0:1] != ("127.0.0.1",)
                or relay_record.get("helloForwardedBytes") != 43 or not isinstance(relay_record.get("helloPrefixHex"), str)
                or re.fullmatch(r"[0-9a-f]{86}", relay_record["helloPrefixHex"]) is None):
            raise AssertionError("No complete existing ClientHello was actually written to that approved upstream")
        random = client_hello_random(bytes.fromhex(relay_record["helloPrefixHex"]))
        record = by_random.get(random); label = relay_record.get("identityProvider")
        peer = (label, tuple(relay_record.get("tlsPeer", [])))
        if (record is None or label != ("first" if record["provider"] == 0 else "second") or peer not in peers or peer in by_peer
                or relay_record.get("targetPort") != record["port"]
                or relay_record["helloPrefixHex"] != record["clientHelloPrefixHex"]):
            raise AssertionError("Client random borrowed a different provider/TCP peer/CONNECT node")
        count = sum((provider, tuple(query_peer)) == peer for provider, _, _, query_peer in observed["queryDetails"])
        if count != record["httpSends"] or ((peer in ready) != (record["nativeResult"] == "success")):
            raise AssertionError("Native application writes/TLS result disagree with that exact server peer")
        by_peer[peer] = record
        if record["provider"] == 0:
            denied.add(peer)
    if set(by_peer) != peers or len({record["token"] for record in by_peer.values()}) != 4:
        raise AssertionError("Unbound/extra provider peer lacks exact identity evidence")
    ssl_errors = observed.get("identitySSLErrors", [])
    indices = set(); error_peers = set(); legacy_rejected = []
    for error in ssl_errors:
        peer = (error.get("provider"), tuple(error.get("peer", []))); index = error.get("errorIndex")
        if (peer not in denied or peer in ready or peer in error_peers or error.get("phase") != "tls-handshake"
                or error.get("actualSSLError") is not True or error.get("errorType") not in {"ssl.SSLEOFError", "ssl.SSLError"}
                or error.get("authenticated") is not False or type(index) is not int or index in indices
                or not 0 <= index < len(observed["errors"])):
            raise AssertionError("An unknown/unbound/application SSL error cannot borrow a certificate-denial proof")
        if error["errorType"] == "ssl.SSLError":
            legacy_rejected.append("first")
        indices.add(index); error_peers.add(peer)
    if (error_peers != denied or indices != set(range(len(observed["errors"])))
            or list(observed["identityRejected"]) != legacy_rejected):
        raise AssertionError("Missing certificate/SSL peer, hidden original error or fabricated SAN rejection")
    return ["first", "first"], indices


def capture_functional_witness(details: str, trace: Trace, scenario: str) -> None:
    """Require the fixed CLI's bounded answer + real callback observations.

    NativeDebug contributes registered candidate/ordinal ordering, not a peer
    identity and not permission to ignore a partial CONNECT or any SSL error.
    """
    marker = "DNS-ADAPTIVE-FUNCTIONAL "
    rows = [line[len(marker):] for line in details.splitlines() if line.startswith(marker)]
    if len(rows) != 1 or len(rows[0].encode("utf-8")) > 16_384:
        raise AssertionError("Functional CLI must emit exactly one bounded witness")
    try:
        witness = json.loads(rows[0])
    except (ValueError, UnicodeError) as error:
        raise AssertionError("Functional CLI witness is not its complete JSON object") from error
    with trace.lock:
        trace.functional_witness = witness if isinstance(witness, dict) else {"observationError": "invalid-object"}
    if (not isinstance(witness, dict) or witness.get("fixtureOnly") is not True
            or type(witness.get("formatVersion")) is not int or witness["formatVersion"] != 1
            or witness.get("scenario") != scenario or witness.get("successAssertionsCompleted") is not True):
        raise AssertionError("Functional CLI did not complete its strict answer/ID/cache/deadline assertions")
    names = ("transactions", "upstreamAttempts", "failovers", "connectionReuse", "dnsFailures", "capacityFailures",
             "timeoutFailures", "rawReady", "tlsReady", "tlsFailures", "wireQueries", "invalidObservations")
    if any(type(witness.get(name)) is not int or witness[name] < 0 for name in names):
        raise AssertionError("Functional observations lost their typed bounded integer counters")
    answers = witness.get("answers")
    if (witness["transactions"] != 6 or not isinstance(answers, list) or len(answers) != 5
            or any(not isinstance(row, list) or len(row) != 2 or type(row[0]) is not int
                   or row[1] not in {"203.0.113.80", "203.0.113.81"} for row in answers)
            or {row[0] for row in answers} != {0x7201, 0x7202, 0x7203, 0x7204, 0x7206}
            or dict(answers)[0x7204] != dict(answers)[0x7201]
            or dict(answers)[0x7202] != "203.0.113.81" or dict(answers)[0x7203] != "203.0.113.81"):
        raise AssertionError("Functional answers changed an ID, approved address, selected fast provider or warm cache winner")
    logical = witness.get("logical")
    if (not isinstance(logical, dict) or any(type(logical.get(key)) is not int for key in
            ("leaders", "cacheHits", "active", "queued", "pending", "waiting"))
            or logical != {"leaders": 4, "cacheHits": 1, "active": 0, "queued": 0, "pending": 0, "waiting": 0}
            or witness["dnsFailures"] != 0 or witness["capacityFailures"] != 0 or witness["timeoutFailures"] != 0
            or witness["tlsFailures"] != 0 or witness["invalidObservations"] != 0):
        raise AssertionError("Functional governor retained pending work or failed capacity/deadline/identity checks")
    attempt_pattern = re.compile(r"^\[HajimiNative\] dns adaptive attempt candidate_index=(\d+) ordinal=(\d+) active=(\d+) .* reason=(\S+)$")
    response_pattern = re.compile(r"^\[HajimiNative\] dns adaptive response candidate_index=(\d+) elapsed_ms=(\d+) rcode=(\d+)$")
    finish_pattern = re.compile(r"^\[HajimiNative\] dns adaptive finish elapsed_ms=(\d+) attempts=(\d+) reason=answer rcode=(\d+)$")
    leaders = [0x7201, 0x7202, 0x7203, 0x7206]
    exchanges, current = [], None
    for line in details.splitlines():
        if match := attempt_pattern.match(line):
            candidate, ordinal, active = map(int, match.groups()[:3])
            reason = match.group(4)
            if candidate not in {0, 1} or not 1 <= active <= 2 or not 1 <= ordinal <= 2:
                raise AssertionError("Functional candidate start escaped the two approved/live attempt bounds")
            if ordinal == 1:
                if (current is not None and not current.get("finished")) or len(exchanges) >= len(leaders):
                    raise AssertionError("Functional CLI started an unregistered/unfinished logical exchange")
                current = {"queryID": leaders[len(exchanges)], "attempts": [], "finished": False}
                exchanges.append(current)
            if current is None or current["finished"] or ordinal != len(current["attempts"]) + 1:
                raise AssertionError("Functional candidate dial started after finish or lost its registered ordinal")
            if any(row["candidateIndex"] == candidate for row in current["attempts"]):
                raise AssertionError("Functional exchange repeated an approved candidate instead of staying bounded")
            if reason != ("initial" if ordinal == 1 else "soft-budget"):
                raise AssertionError("Functional speculation was not its registered initial/soft-hedge attempt")
            current["attempts"].append({"candidateIndex": candidate, "ordinal": ordinal, "activeAtStart": active,
                                        "reason": reason})
        elif match := response_pattern.match(line):
            candidate, elapsed, code = map(int, match.groups())
            if (current is None or current["finished"] or code != 0 or elapsed >= 8000
                    or candidate not in {row["candidateIndex"] for row in current["attempts"]}):
                raise AssertionError("Functional winner was unregistered, post-finish, failed or expired")
            current["winnerCandidateIndex"] = candidate
        elif match := finish_pattern.match(line):
            elapsed, attempts, code = map(int, match.groups())
            if (current is None or current["finished"] or code != 0 or elapsed >= 8000
                    or attempts != len(current["attempts"]) or "winnerCandidateIndex" not in current):
                raise AssertionError("Functional finish did not follow its exact registered successful attempts")
            current.update({"finished": True, "elapsedMilliseconds": elapsed})
    if (len(exchanges) != 4 or any(not item["finished"] for item in exchanges)
            or sum(len(item["attempts"]) for item in exchanges) != witness["upstreamAttempts"]
            or witness["failovers"] != witness["upstreamAttempts"] - 4):
        raise AssertionError("Functional CLI lacked the complete four-exchange registered attempt ledger")
    for item in exchanges:
        expected = "203.0.113.80" if item["winnerCandidateIndex"] == 0 else "203.0.113.81"
        if dict(answers)[item["queryID"]] != expected:
            raise AssertionError("Functional client answer did not come from its registered winning provider")
    for name in ("connectionStage", "tlsStage"):
        stage = witness.get(name)
        if (not isinstance(stage, dict) or any(type(stage.get(key)) is not int or stage[key] < 0
                for key in ("count", "failures", "cancelled")) or stage["failures"] != 0
                or stage["cancelled"] > stage["count"]):
            raise AssertionError("Functional native stage receipts hid failures or invented cancellation ACKs")
    if scenario == "production-success" and (
            witness["connectionStage"]["count"] != witness["upstreamAttempts"] - witness["connectionReuse"]
            or not 3 <= witness["connectionStage"]["count"] <= 5
            or witness["rawReady"] != witness["tlsReady"]
            or witness["tlsStage"]["count"] != witness["rawReady"]):
        raise AssertionError("Functional native dial reservations did not retire at their actual connection/TLS callbacks")
    witness["registeredExchanges"] = exchanges
    with trace.lock:
        trace.functional_witness = witness


def validate_functional_success_trace(observed: dict, production: bool, endpoint_ports: dict[str, int]) -> int:
    """Both cold providers are valid only for the exact registered wire ID.

    A payload-free pre-CONNECT EOF is classified only by the complete
    registered loser/real callback receipt ledger and the approved node
    endpoint. This is not an ordinal-to-local-port or kernel TCP ACK claim.
    """
    witness = observed["functionalWitness"]
    peers = [(label, tuple(peer)) for label, peer in observed["tlsPeers"]]
    questions = [(label, name, identifier, tuple(peer)) for label, name, identifier, peer in observed["queryDetails"]]
    responses = [(label, name, identifier, tuple(peer)) for label, name, identifier, peer in observed["responseDetails"]]
    if (observed["identityRejected"] or observed["proxyRejected"] or observed["plaintext"] != 0 or observed["errors"]
            or observed["tlsHandlersActive"] != 0 or observed["wireActive"] != 0
            or observed.get("connectFailures")):
        raise AssertionError("Functional DNS failed identity, CONNECT framing, SSL, privacy or physical teardown")
    if (not 2 <= len(peers) <= 5 or len(set(peers)) != len(peers)
            or observed["tls"] != [label for label, _ in peers]
            or any(label not in {"first", "second"} or len(peer) != 2 or peer[0] != "127.0.0.1"
                   or type(peer[1]) is not int or not 0 < peer[1] <= 65535 for label, peer in peers)
            or Counter((label, tuple(peer)) for label, peer in observed["tlsReady"]) != Counter(peers)
            or Counter((label, tuple(peer)) for label, peer in observed["tlsClosed"]) != Counter(peers)):
        raise AssertionError("Functional TLS carriers exceeded the original five admitted/verified/closed peer bound")
    names = {0x7201: "adaptive.cold.example.test", 0x7202: "adaptive.discover.example.test",
             0x7203: "adaptive.preferred.example.test", 0x7206: "adaptive.cold.example.test"}
    exchanges = {item["queryID"]: item for item in witness["registeredExchanges"]}
    candidate_counts = Counter("first" if row["candidateIndex"] == 0 else "second"
                               for item in exchanges.values() for row in item["attempts"])
    if any(count > candidate_counts[label] for label, count in Counter(label for label, _ in peers).items()):
        raise AssertionError("Functional TLS peer had no registered admitted provider attempt")
    if (not 4 <= len(questions) <= 6 or len(set((label, identifier) for label, _, identifier, _ in questions)) != len(questions)
            or [(label, name) for label, name, _, _ in questions] != [tuple(item) for item in observed["queries"]]
            or [(label, name, peer) for label, name, _, peer in questions]
            != [(label, name, tuple(peer)) for label, name, peer in observed["queryPeers"]]
            or not Counter(responses) <= Counter(questions)):
        raise AssertionError("Functional wire queries/answers duplicated, lost an ID or escaped registered ownership")
    for label, name, identifier, peer in questions:
        if (identifier not in names or names[identifier] != name or (label, peer) not in set(peers)
                or (0 if label == "first" else 1) not in
                {row["candidateIndex"] for row in exchanges[identifier]["attempts"]}):
            raise AssertionError("Functional DNS ID/QNAME/provider/peer was not its registered admitted attempt")
    answers = dict(witness["answers"])
    for identifier in names:
        winner = "first" if answers[identifier] == "203.0.113.80" else "second"
        if sum(label == winner and observed_id == identifier for label, _, observed_id, _ in responses) != 1:
            raise AssertionError("Functional client answer did not belong to its actual authenticated server response")
    second_peers = [peer for label, _, identifier, peer in questions if identifier in {0x7202, 0x7203} and label == "second"]
    old_peers = {peer for _, _, identifier, peer in questions if identifier != 0x7206}
    if (len(second_peers) != 2 or second_peers[0] != second_peers[1]
            or any(peer in old_peers for _, _, identifier, peer in questions if identifier == 0x7206)):
        raise AssertionError("Functional preference did not reuse the fast peer or flush used an old carrier")
    queried = {(label, peer) for label, _, _, peer in questions}
    empty = set(peers) - queried
    preconnect_empty = validate_preconnect_empty_cancellations(observed, witness, production)
    if len(empty) + preconnect_empty > 2:
        raise AssertionError("Functional empty TLS speculation exceeded the original two-carrier bound")
    expected_connects = Counter(("127.0.0.1", endpoint_ports[label]) for label, _ in peers) if production else Counter()
    if (Counter(tuple(row) for row in observed["connects"]) != expected_connects
            or observed["proxyPeers"] != ["127.0.0.1"] * (sum(expected_connects.values()) + preconnect_empty)):
        raise AssertionError("Functional CONNECT peers lacked the exact registered approved TLS endpoint outcome")
    if production and (witness["rawReady"] != len(peers) or witness["wireQueries"] != len(questions)):
        raise AssertionError("Independent client callback/send observations disagree with actual authenticated server carriers")
    return len(empty) + preconnect_empty


def validate_preconnect_empty_cancellations(observed: dict, witness: dict, production: bool) -> int:
    rows = observed.get("proxyConnections", [])
    if not isinstance(rows, list):
        raise AssertionError("Proxy connection observations are not their bounded per-peer ledger")
    cancelled = [row for row in rows if row.get("preConnectEmptyEOF") is True]
    if not cancelled:
        return 0  # A cancelled dial before accept is not extra server I/O.
    endpoint = observed.get("approvedProxyEndpoint")
    elapsed = observed.get("elapsedSeconds")
    if (not production or not isinstance(endpoint, (list, tuple)) or len(endpoint) != 2
            or endpoint[0] != "127.0.0.1" or type(endpoint[1]) is not int or not 0 < endpoint[1] <= 65535
            or type(observed.get("proxyHandlersActive")) is not int or observed["proxyHandlersActive"] != 0
            or type(elapsed) not in {int, float} or not math.isfinite(elapsed) or elapsed < 0
            or not 1 <= len(cancelled) <= 2 or len(rows) != len(observed["proxyPeers"])
            or len(rows) > 5 or len({tuple(row.get("peer", [])) for row in rows}) != len(rows)):
        raise AssertionError("Pre-CONNECT empty peer escaped its approved node endpoint, original dial bound or actual handler drain")
    for row in cancelled:
        peer = row.get("peer")
        if (not isinstance(peer, (list, tuple)) or len(peer) != 2 or peer[0] != "127.0.0.1"
                or type(peer[1]) is not int or not 0 < peer[1] <= 65535
                or tuple(row.get("proxyEndpoint", [])) != tuple(endpoint)
                or type(row.get("receivedBytes")) is not int or row["receivedBytes"] != 0
                or row.get("cleanEOF") is not True or row.get("connectHeaderComplete") is not False
                or row.get("targetPort") is not None or row.get("upstreamOpened") is not False
                or type(row.get("acceptedSeconds")) not in {int, float}
                or type(row.get("closedSeconds")) not in {int, float}
                or not math.isfinite(row["acceptedSeconds"]) or not math.isfinite(row["closedSeconds"])
                or not 0 <= row["acceptedSeconds"] <= row["closedSeconds"] <= elapsed):
            raise AssertionError("Pre-CONNECT cancellation carried a partial header/data, lacked clean EOF or did not actually close")
    stage = witness["connectionStage"]
    losers = sum(len(item["attempts"]) == 2 and any(row["reason"] == "soft-budget" for row in item["attempts"])
                 for item in witness["registeredExchanges"])
    if (len(cancelled) > losers or stage["cancelled"] != len(cancelled)
            or stage["count"] - witness["tlsReady"] != len(cancelled)):
        raise AssertionError("Empty peer count had no exact registered soft-hedge loser and real pre-TLS cancellation receipt")
    return len(cancelled)


def validate_source_scope_wire_trace(observed: dict, production: bool, endpoint_ports: dict[str, int]) -> None:
    """Single-approved-provider pooling oracle; second is an unapproved probe.

    Logical clients/capacity are independently checked by the genuine Core
    governor. Two-provider adaptive selection remains a separate scenario.
    Here we require actual questions, authenticated TLS carriers, native
    CONNECTs and a physical close fence, with zero I/O to the second server.
    """
    peers = [(label, tuple(peer)) for label, peer in observed["tlsPeers"]]
    ready = [(label, tuple(peer)) for label, peer in observed["tlsReady"]]
    closed = [(label, tuple(peer)) for label, peer in observed["tlsClosed"]]
    questions = [(label, name, identifier, tuple(peer)) for label, name, identifier, peer in observed["queryDetails"]]
    responses = [(label, name, identifier, tuple(peer)) for label, name, identifier, peer in observed["responseDetails"]]
    connects = [tuple(item) for item in observed["connects"]]
    if (not production or observed["identityRejected"] or observed["proxyRejected"] or observed["errors"]
            or observed["plaintext"] != 0 or observed["tlsHandlersActive"] != 0 or observed["wireActive"] != 0):
        raise AssertionError("Source-scope fixture failed identity/privacy/physical teardown")
    if (not 3 <= len(peers) <= 66 or len(set(peers)) != len(peers)
            or list(observed["tls"]) != [label for label, _ in peers]
            or any(label != "first" or len(peer) != 2 or peer[0] != "127.0.0.1"
                   or not isinstance(peer[1], int) or not 0 < peer[1] <= 65535 for label, peer in peers)
            or Counter(ready) != Counter(peers) or Counter(closed) != Counter(peers)):
        raise AssertionError("Source scopes created excess/unverified/off-loopback TLS carriers or healthy secondary hedges")
    if (Counter(connects) != Counter([("127.0.0.1", endpoint_ports["first"])] * len(peers))
            or observed["proxyPeers"] != ["127.0.0.1"] * len(peers)):
        raise AssertionError("Real source-scope CONNECT/TLS carrier counts or approved endpoint differ")
    if (len(questions) != 353 or len(responses) != 353 or Counter(responses) != Counter(questions)
            or [(label, name) for label, name, _, _ in questions] != [tuple(item) for item in observed["queries"]]
            or [(label, name, peer) for label, name, _, peer in questions]
            != [(label, name, tuple(peer)) for label, name, peer in observed["queryPeers"]]
            or any(label != "first" or (label, peer) not in set(ready) for label, _, _, peer in questions)):
        raise AssertionError("Source-scope DNS answers/questions did not belong to their authenticated real TLS carrier")
    shared = [item for item in questions if item[1] == "scope.shared.example.test" and 0x7400 <= item[2] < 0x74C0]
    if len(shared) != 96 or Counter((item[2] - 0x7400) // 2 for item in shared) != Counter(range(96)):
        raise AssertionError("Source cache/coalescing crossed client tuples or failed within a source scope")
    burst = [item for item in questions if item[1].startswith("scope.burst-")]
    if (len(burst) != 256 or Counter((item[1], item[2]) for item in burst)
            != Counter((f"scope.burst-{index}.example.test", 0x7600 + index) for index in range(256))):
        raise AssertionError("256 original/source-scope burst lost, repeated or changed DNS questions/IDs")
    fresh = [item for item in questions if item[1] == "scope.shared.example.test" and item[2] == 0x7701]
    if len(fresh) != 1 or len(shared) + len(burst) + len(fresh) != len(questions):
        raise AssertionError("Warm cache or QNAME REJECT caused wire I/O, or flush did not cause one fresh query")
    queried_carriers = {(label, peer) for label, _, _, peer in questions}
    empty = set(peers) - queried_carriers
    if len(empty) != 1 or len(questions) - len(queried_carriers) < 288:
        raise AssertionError("Source scopes amplified handshakes or real encrypted connection reuse was not observed")
    acknowledgements = observed.get("preflightACKs", [])
    if (len(acknowledgements) != 1 or len(acknowledgements[0]) != 3
            or (acknowledgements[0][0], tuple(acknowledgements[0][1])) not in empty
            or (acknowledgements[0][0], tuple(acknowledgements[0][1])) != peers[0]
            or acknowledgements[0][2] != SOURCE_SCOPE_PREFLIGHT_ACK.hex()):
        raise AssertionError("The sole empty preflight must receive exactly its authenticated post-handshake ACK")
    if not 1 <= observed["wirePeak"] <= 16:
        raise AssertionError("Server observed more than 16 healthy physical DNS exchanges at once")
    checkpoints = observed["scopeCheckpoints"]
    if len(checkpoints) != 1:
        raise AssertionError("Source-scope case did not physically fence exactly one flush")
    fence = checkpoints[0]
    old_peers = {(label, tuple(peer)) for label, peer in fence["closedPeers"]}
    if (fence["version"] != 1 or fence["phase"] != "flush-closed" or not 2 <= fence["tlsStarted"] <= 65
            or fence["tlsClosed"] != fence["tlsStarted"] or fence["tlsReady"] != fence["tlsStarted"]
            or len(old_peers) != fence["tlsStarted"] or fence["clientHTTPQueries"] != 352
            or fence["serverQuestions"] != 352 or fence["serverAnswers"] != 352
            or fence["tlsHandlersActive"] != 0 or fence["connectHandlersActive"] != 0
            or fence["traditionalQueries"] != 0 or old_peers != set(peers) - {(fresh[0][0], fresh[0][3])}
            or (fresh[0][0], fresh[0][3]) in old_peers or not empty.issubset(old_peers)):
        raise AssertionError("Flush fresh query raced an old still-open server TLS/CONNECT carrier")


def parse_carrier_proof(proof: dict) -> dict[str, dict]:
    """Complete actual native results; never infer cancellation from text/domain."""
    if (not isinstance(proof, dict) or type(proof.get("formatVersion")) is not int or proof["formatVersion"] != 1
            or proof.get("fixtureOnly") is not True or proof.get("recordLimit") != 128
            or tuple(proof.get("columns", [])) != CARRIER_PROOF_COLUMNS
            or proof.get("tlsFailures") != 0 or proof.get("preludeFailures") != 0):
        raise AssertionError("Carrier proof is incomplete or contains actual unknown/auth/prelude failure")
    rows = proof.get("records")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 128 or proof.get("rawReady") != len(rows):
        raise AssertionError("Carrier proof omitted actual raw owners")
    result = {}; successes = aborted = 0
    for index, row in enumerate(rows):
        if not isinstance(row, list) or len(row) != len(CARRIER_PROOF_COLUMNS):
            raise AssertionError("Carrier proof changed its fixed bounded schema")
        item = dict(zip(CARRIER_PROOF_COLUMNS, row))
        if (not isinstance(item["nonce"], str) or NONCE_PATTERN.fullmatch(item["nonce"]) is None
                or item["nonce"] in result or type(item["ordinal"]) is not int or item["ordinal"] != index
                or type(item["provider"]) is not int or item["provider"] not in {0, 1}
                or type(item["httpQueries"]) is not int or item["httpQueries"] < 0
                or type(item["observerAuthenticationCount"]) is not int or item["observerAuthenticationCount"] != 0
                or item["preludeFailure"] is not False or type(item["boundTypedAbort"]) is not bool):
            raise AssertionError("Carrier proof lost identity, authentication or HTTP ownership")
        for name in ("bindingACK", "nativeTLSStarted", "nativeResultAt", "handoffAt"):
            if type(item[name]) not in {int, float} or not math.isfinite(item[name]) or item[name] < 0:
                raise AssertionError("Native TLS never started/completed after a real nonce ACK")
        if not item["bindingACK"] <= item["nativeTLSStarted"] <= item["nativeResultAt"] <= item["handoffAt"]:
            raise AssertionError("Carrier proof fabricated a phase or native completion order")
        for name in ("explicitCancel", "firstObserverDeny"):
            if item[name] is not None and (type(item[name]) not in {int, float}
                                          or not math.isfinite(item[name]) or item[name] < 0):
                raise AssertionError("Cancellation/observer proof is not its actual monotonic metadata")
        if item["nativeResult"] == "success":
            if item["boundTypedAbort"] or any(item[key] is not None for key in
                                               ("nativeCase", "NSErrorDomain", "NSErrorCode", "classification")):
                raise AssertionError("A canceled/unknown native result was relabelled authenticated success")
            successes += 1
        elif (item["nativeResult"] == "failure" and item["nativeCase"] == "cancelled"
              and item["classification"] == "cancelled" and item["NSErrorDomain"] == "HajimiCore.NativeOutboundError"
              and type(item["NSErrorCode"]) is int and item["NSErrorCode"] == 4 and item["boundTypedAbort"] is True
              and item["httpQueries"] == 0 and item["explicitCancel"] is not None
              and item["nativeTLSStarted"] <= item["explicitCancel"] <= item["nativeResultAt"]
              and (item["firstObserverDeny"] is None or item["firstObserverDeny"] > item["explicitCancel"])):
            # Swift supplies nativeCase only for the actual enum; an NSError
            # with the same domain/code, cancel flag or message is insufficient.
            aborted += 1
        else:
            raise AssertionError("Unknown/authentication/native result cannot be washed into own cancellation")
        result[item["nonce"]] = item
    if proof.get("tlsReady") != successes or proof.get("typedTLSCancelled") != aborted:
        raise AssertionError("Complete native ready/non-success/raw counters disagree")
    return result


def validate_bound_carrier_peers(observed: dict, proof: dict) -> set[tuple[str, tuple]]:
    records = parse_carrier_proof(proof)
    peers = {(label, tuple(peer)) for label, peer in observed["tlsPeers"]}
    ready = {(label, tuple(peer)) for label, peer in observed["tlsReady"]}
    closed = {(label, tuple(peer)) for label, peer in observed["tlsClosed"]}
    bindings = observed.get("carrierBindings", [])
    if not isinstance(bindings, list) or len(bindings) != len(records) or closed != peers:
        raise AssertionError("Unbound raw peer or incomplete actual server socket closure")
    by_peer = {}; by_nonce = {}; canceled = set()
    for binding in bindings:
        nonce = binding.get("nonce"); item = records.get(nonce)
        peer = (binding.get("provider"), tuple(binding.get("peer", [])))
        if (item is None or peer not in peers or peer in by_peer or nonce in by_nonce
                or binding.get("extraProtocol") is not True or binding.get("ordinal") != item["ordinal"]
                or binding.get("provider") != ("first" if item["provider"] == 0 else "second")):
            raise AssertionError("Nonce proof is not bound to that exact real provider/TCP peer")
        by_peer[peer] = item; by_nonce[nonce] = peer
        if item["boundTypedAbort"]: canceled.add(peer)
        elif peer not in ready:
            raise AssertionError("Native success did not authenticate its actual server TLS carrier")
        if item["httpQueries"] != sum((label, tuple(query_peer)) == peer for label, _, _, query_peer in observed["queryDetails"]):
            raise AssertionError("Actual native HTTP writes disagree with that bound server's query ledger")
    if set(by_peer) != peers or not ready.issubset(peers):
        raise AssertionError("Unbound/unapproved extra TLS peer")
    if any((label, tuple(peer)) in canceled for label, _, _, peer in observed["queryDetails"]):
        raise AssertionError("A canceled native handshake carried HTTP/DNS application payload")
    eofs = observed.get("handshakeEOFs", []); indices = set(); eof_peers = set()
    for eof in eofs:
        peer = (eof.get("provider"), tuple(eof.get("peer", []))); index = eof.get("errorIndex")
        if (peer not in canceled or peer in ready or peer in eof_peers or eof.get("nonce") not in by_nonce
                or by_nonce[eof["nonce"]] != peer or eof.get("ordinal") != by_peer[peer]["ordinal"]
                or eof.get("errorType") != "ssl.SSLEOFError" or eof.get("authenticated") is not False
                or type(eof.get("httpPayloadBytes")) is not int or eof["httpPayloadBytes"] != 0
                or type(index) is not int or index in indices or not 0 <= index < len(observed["errors"])):
            raise AssertionError("Unbound/partial/unknown SSL error cannot borrow another carrier's typed cancellation")
        indices.add(index); eof_peers.add(peer)
    if eof_peers != peers - ready or indices != set(range(len(observed["errors"]))):
        raise AssertionError("A real SSL/unknown error or non-ready peer lacks exact native cancellation proof")
    return canceled


def validate_multi_upstream_wire_trace(observed: dict, production: bool, endpoint_ports: dict[str, int],
                                     scenario: str) -> None:
    """Independent two-approved-provider pressure oracle, including ownership.

    An authenticated .80 or .81 is allowed only when that exact transaction
    reached the corresponding admitted provider/real TLS peer. The old
    single-provider oracle and its limits are deliberately unchanged.
    """
    if scenario not in MULTI_UPSTREAM_SCENARIOS or set(endpoint_ports) != {"first", "second"}:
        raise AssertionError("Unknown or unbounded multi-upstream authority set")
    peers = [(label, tuple(peer)) for label, peer in observed["tlsPeers"]]
    ready = [(label, tuple(peer)) for label, peer in observed["tlsReady"]]
    closed = [(label, tuple(peer)) for label, peer in observed["tlsClosed"]]
    questions = [(label, name, identifier, tuple(peer)) for label, name, identifier, peer in observed["queryDetails"]]
    responses = [(label, name, identifier, tuple(peer)) for label, name, identifier, peer in observed["responseDetails"]]
    failures = [tuple(row) for row in observed["connectFailures"]]
    connects = [tuple(row) for row in observed["connects"]]
    if (not production or observed["identityRejected"] or observed["proxyRejected"]
            or observed["plaintext"] != 0 or observed["tlsHandlersActive"] != 0 or observed["wireActive"] != 0):
        raise AssertionError("Multi-upstream fixture failed closed identity/privacy/physical teardown checks")
    validate_bound_carrier_peers(observed, observed.get("carrierProof"))
    if (not 3 <= len(peers) <= 67 or len(set(peers)) != len(peers)
            or observed["tls"] != [label for label, _ in peers]
            or any(label not in endpoint_ports or len(peer) != 2 or peer[0] != "127.0.0.1"
                   or type(peer[1]) is not int or not 0 < peer[1] <= 65535 for label, peer in peers)
            or len(set(ready)) != len(ready) or Counter(closed) != Counter(peers)):
        raise AssertionError("Multi-upstream TLS escaped admitted providers, verification, bounds or terminal close")
    connect_failure = scenario == "multi-upstream-connect-failure-burst"
    if connect_failure:
        if (not failures or any(row != ("127.0.0.1", endpoint_ports["first"], 503) for row in failures)
                or any(label != "second" for label, _ in peers)):
            raise AssertionError("Injected first CONNECT outage contacted its forbidden TLS server or changed error framing")
    elif failures or {label for label, _ in peers} != {"first", "second"}:
        raise AssertionError("Slow-carrier pressure did not authenticate both admitted providers")
    expected_connects = Counter(("127.0.0.1", endpoint_ports[label]) for label, _ in peers)
    expected_connects.update((host, port) for host, port, _ in failures)
    if Counter(connects) != expected_connects or observed["proxyPeers"] != ["127.0.0.1"] * len(connects):
        raise AssertionError("Admitted CONNECT outcomes do not match each actual provider TLS carrier or framed outage")
    if (not 353 <= len(questions) <= 706 or Counter(questions) != Counter(responses)
            or [(label, name) for label, name, _, _ in questions] != [tuple(item) for item in observed["queries"]]
            or [(label, name, peer) for label, name, _, peer in questions]
            != [(label, name, tuple(peer)) for label, name, peer in observed["queryPeers"]]
            or any(label not in endpoint_ports or (label, peer) not in set(ready)
                   or type(identifier) is not int for label, _, identifier, peer in questions)):
        raise AssertionError("Multi-upstream query/answer did not retain its ID and authenticated approved provider/peer")
    shared = [item for item in questions if item[1] == "scope.shared.example.test" and 0x7400 <= item[2] < 0x74C0]
    burst = [item for item in questions if item[1].startswith("scope.burst-")]
    fresh = [item for item in questions if item[1] == "scope.shared.example.test" and item[2] == 0x7701]
    if (not 96 <= len(shared) <= 192 or not 256 <= len(burst) <= 512
            or not 1 <= len(fresh) <= 2 or len(shared) + len(burst) + len(fresh) != len(questions)):
        raise AssertionError("Multi-upstream answer cache/coalescing crossed sources, duplicated IDs or admitted REJECT/warm I/O")
    groups = {}
    for item in shared:
        groups.setdefault(("shared", (item[2] - 0x7400) // 2), []).append(item)
    for item in burst:
        index = item[2] - 0x7600
        if not 0 <= index < 256 or item[1] != f"scope.burst-{index}.example.test":
            raise AssertionError("Burst QNAME/source/ID mapping changed")
        groups.setdefault(("burst", index), []).append(item)
    groups[("fresh", 0)] = fresh
    expected_groups = {("shared", i) for i in range(96)} | {("burst", i) for i in range(256)} | {("fresh", 0)}
    if set(groups) != expected_groups:
        raise AssertionError("A source-scope leader was lost or coalesced with another source")
    for rows in groups.values():
        # Fixed literal two-provider profile: each candidate is consumed once
        # by the <=3-attempt/<=2-active production selector. A wire question
        # can therefore reach both authenticated providers, never silently
        # retry the same provider or switch the coalesced source's actual ID.
        if not 1 <= len(rows) <= 2 or len({row[0] for row in rows}) != len(rows) or len({row[2] for row in rows}) != 1:
            raise AssertionError("Unproved same-provider duplicate, >2 active candidates, or source/ID ownership loss")
    queried_carriers = {(label, peer) for label, _, _, peer in questions}
    empty = set(peers) - queried_carriers
    ack = observed.get("preflightACKs", [])
    expected_preflight = "second" if connect_failure else "first"
    if (len(ack) != 1 or len(ack[0]) != 3 or (ack[0][0], tuple(ack[0][1])) != peers[0]
            or peers[0][0] != expected_preflight or peers[0] not in empty
            or ack[0][2] != SOURCE_SCOPE_PREFLIGHT_ACK.hex()
            or len(questions) - len(queried_carriers) < 288 or not 1 <= observed["wirePeak"] <= 32):
        raise AssertionError("Multi-upstream workload lost its authenticated preflight or amplified healthy DNS carriers")
    checkpoints = observed["scopeCheckpoints"]
    if len(checkpoints) != 1:
        raise AssertionError("Multi-upstream pressure did not physically fence exactly one flush")
    fence = checkpoints[0]
    old_peers = {(label, tuple(peer)) for label, peer in fence["closedPeers"]}
    new_peers = set(peers) - old_peers
    fresh_carriers = 1 if connect_failure else 2
    if (fence.get("version") != 1 or fence.get("phase") != "flush-closed"
            or not 2 <= fence["tlsStarted"] <= 65 or not 1 <= fence["tlsReady"] <= fence["tlsStarted"]
            or fence["tlsClosed"] != fence["tlsStarted"] or len(old_peers) != fence["tlsStarted"]
            or fence["clientHTTPQueries"] != len(shared) + len(burst)
            or fence["serverQuestions"] != len(shared) + len(burst)
            or fence["serverAnswers"] != len(shared) + len(burst) or fence["traditionalQueries"] != 0
            or fence["tlsHandlersActive"] != 0 or fence["connectHandlersActive"] != 0
            or not 2 <= fence["connectAttempts"] <= 65
            or fence["connectAttempts"] != fence["tlsStarted"] + fence["connectFailures"]
            or len(new_peers) != fresh_carriers or (fresh[0][0], fresh[0][3]) not in new_peers
            or peers[0] not in old_peers or not old_peers.issubset(set(peers))
            or any((label, peer) not in old_peers for label, _, _, peer in shared + burst)):
        raise AssertionError("Multi-upstream fresh epoch reused an old answer/carrier or its close ACK was only logical")
    answers = observed.get("multiUpstreamClientAnswers")
    if (not isinstance(answers, list) or len(answers) != 450
            or any(not isinstance(row, list) or len(row) != 2 or type(row[0]) is not int
                   or row[1] not in {"203.0.113.80", "203.0.113.81"} for row in answers)
            or len({row[0] for row in answers}) != len(answers)):
        raise AssertionError("Multi-upstream client answer ledger is missing, duplicated or outside the approved address set")
    actual = dict(answers); expected_ids = {0x7400 + i for i in range(192)} | {0x7500, 0x7701} | {0x7600 + i for i in range(256)}
    if set(actual) != expected_ids or actual[0x7500] != actual[0x7400]:
        raise AssertionError("Client response or warm cache did not belong to that exact authenticated source-scope/provider transaction")
    for (kind, index), rows in groups.items():
        permitted_addresses = {"203.0.113.80" if row[0] == "first" else "203.0.113.81" for row in rows}
        if kind == "shared":
            first_id = 0x7400 + index * 2
            if actual[first_id] != actual[first_id + 1] or actual[first_id] not in permitted_addresses:
                raise AssertionError("Merged clients did not retain the actual authenticated winner of their own source")
        else:
            identifier = 0x7701 if kind == "fresh" else 0x7600 + index
            if actual[identifier] not in permitted_addresses:
                raise AssertionError("Client winner did not have that exact provider/QNAME/ID authenticated reply")


class HandlerDrainTracker:
    """Track admission before worker scheduling, plus one listener loop turn."""
    def __init__(self, *arguments, **options):
        self._drain = threading.Condition()
        self._active_handlers = 0
        self._listener_turn = 0
        self._listener_idle = False
        super().__init__(*arguments, **options)

    def process_request(self, request, client_address) -> None:
        with self._drain:
            self._active_handlers += 1
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self._drain:
                self._active_handlers -= 1
                self._drain.notify_all()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._drain:
                self._active_handlers -= 1
                self._drain.notify_all()

    def service_actions(self) -> None:
        super().service_actions()
        pending = bool(select.select([self.socket], [], [], 0)[0])
        with self._drain:
            self._listener_turn += 1
            self._listener_idle = not pending
            self._drain.notify_all()

    def wait_idle(self) -> bool:
        with self._drain:
            turn = self._listener_turn
            return self._drain.wait_for(lambda: self._active_handlers == 0 and self._listener_turn > turn
                                       and self._listener_idle, timeout=2)


def exact(peer: socket.socket, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        data = peer.recv(count - len(result))
        if not data:
            raise AssertionError("TLS peer ended before ClientHello")
        result.extend(data)
    return bytes(result)


class RejectTLS(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        trace: Trace = self.server.trace
        try:
            if self.client_address[0] != "127.0.0.1":
                raise AssertionError("Non-loopback TLS peer")
            self.request.settimeout(10)
            header = exact(self.request, 5)
            if header[0] != 22 or header[1] != 3:
                raise AssertionError("Encrypted provider received non-TLS/plaintext traffic")
            length = int.from_bytes(header[3:5], "big")
            if not 4 <= length <= 18_432:
                raise AssertionError("Unbounded TLS fixture record")
            hello = exact(self.request, length)
            if hello[0] != 1:
                raise AssertionError("First TLS message was not ClientHello")
            with trace.lock:
                trace.hellos.append(self.server.label)
                trace.tls_peers.append((self.server.label, self.client_address))
                trace.event_locked("tls-clienthello-rejected", provider=self.server.label)
            self.request.shutdown(socket.SHUT_RDWR)
        except (AssertionError, OSError) as error:
            with trace.lock:
                trace.errors.append(str(error))
                trace.event_locked("tls-error", provider=self.server.label, error=str(error)[:512])


class PlainDNS(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        with self.server.trace.lock:
            self.server.trace.plaintext += 1
            self.server.trace.event_locked("plaintext-query", peer=self.client_address[0])


def answer(query: bytes, address: str, *, source_scope: bool = False) -> tuple[str, bytes]:
    if not 12 <= len(query) <= 65_535:
        raise AssertionError("Unbounded HTTPS DNS question")
    _identifier, flags, questions, answers, authority, additional = struct.unpack("!6H", query[:12])
    if flags & 0x8000 or (questions, answers, authority, additional) != (1, 0, 0, 0):
        raise AssertionError("Unexpected HTTPS DNS query flags/counts")
    labels, position = [], 12
    while True:
        if position >= len(query):
            raise AssertionError("Truncated DNS fixture name")
        size = query[position]; position += 1
        if size == 0:
            break
        if size > 63 or position + size > len(query):
            raise AssertionError("Compressed or unbounded DNS fixture name")
        labels.append(query[position:position + size].decode("ascii")); position += size
    name = ".".join(labels)
    allowed = {"adaptive.cold.example.test", "adaptive.discover.example.test",
               "adaptive.preferred.example.test", "adaptive.identity.example.test",
               "adaptive.identity-next.example.test"}
    if source_scope:
        identifier = int.from_bytes(query[:2], "big")
        if name == "scope.shared.example.test":
            allowed_name = 0x7400 <= identifier < 0x74C0 or identifier == 0x7701
        elif name.startswith("scope.burst-") and name.endswith(".example.test"):
            literal = name[len("scope.burst-"):-len(".example.test")]
            allowed_name = (literal.isdecimal() and str(int(literal)) == literal
                            and 0 <= int(literal) < 256 and identifier == 0x7600 + int(literal))
        else:
            allowed_name = False
    else:
        allowed_name = name in allowed
    if not allowed_name or position + 4 != len(query) or query[position:] != b"\x00\x01\x00\x01":
        raise AssertionError(f"Unexpected or policy-blocked question reached HTTPS: {name}")
    response = query[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0) + query[12:]
    response += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 120 if source_scope else 60, 4) + socket.inet_aton(address)
    return name, response


class HealthyTLS(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        trace: Trace = self.server.trace
        active_question = False
        binding = None
        with trace.lock:
            trace.tls_active += 1; trace.tls_peak = max(trace.tls_peak, trace.tls_active)
        try:
            if self.client_address[0] != "127.0.0.1":
                raise AssertionError("Non-loopback HTTPS peer")
            # These fixed-loopback peers exchange short TLS/H1 records. Keep
            # the explicit query delay as the only intentional latency; do
            # not introduce a Nagle/delayed-ACK delay in the fixture itself.
            self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.request.settimeout(10)
            with trace.lock:
                preflight_carrier = self.server.source_scope and not trace.tls_peers
                trace.hellos.append(self.server.label)
                trace.tls_peers.append((self.server.label, self.client_address))
                trace.event_locked("tls-handler-start", provider=self.server.label, peer=self.client_address)
            if self.server.bind_carriers:
                # Explicit multi CLI fixture metadata, NOT production/public
                # TLS or HTTP/DNS. The native C++ CONNECT carrier itself reads
                # this exact ACK before starting the unchanged verified TLS.
                frame = exact(self.request, len(BIND_PREFIX) + BIND_SUFFIX_BYTES)
                suffix = frame[len(BIND_PREFIX):]
                if not frame.startswith(BIND_PREFIX) or not suffix.endswith(b"\r\n"):
                    raise AssertionError("Unbound/partial/invalid fixture carrier prelude")
                nonce, provider, ordinal = suffix[:-2].decode("ascii").split(" ")
                expected_provider = "0" if self.server.label == "first" else "1"
                if (NONCE_PATTERN.fullmatch(nonce) is None or provider != expected_provider
                        or re.fullmatch(r"\d{3}", ordinal) is None or not 0 <= int(ordinal) < 128):
                    raise AssertionError("Fixture carrier binding escaped nonce/provider/ordinal bounds")
                binding = {"nonce": nonce, "ordinal": int(ordinal), "provider": self.server.label,
                           "peer": self.client_address, "extraProtocol": True}
                with trace.lock:
                    if len(trace.carrier_bindings) >= 128 or any(row["nonce"] == nonce for row in trace.carrier_bindings):
                        raise AssertionError("Repeated or unbounded fixture carrier nonce")
                    trace.carrier_bindings.append(binding)
                    trace.event_locked("fixture-carrier-bound", **binding)
                self.request.sendall(BIND_ACK_PREFIX + suffix)
            handshake_started = time.monotonic()
            if self.server.source_scope:
                # Peek without consuming bytes or adding protocol traffic.
                # Distinguish a late first ClientHello from time spent waiting
                # for later handshake/verification messages on the same peer.
                prefix = self.request.recv(5, socket.MSG_PEEK)
                with trace.lock:
                    trace.event_locked("tls-first-record-visible", provider=self.server.label,
                                       peer=self.client_address, headerBytesVisible=len(prefix),
                                       waitMilliseconds=round((time.monotonic() - handshake_started) * 1000, 3))
            try:
                peer = self.server.context.wrap_socket(self.request, server_side=True)
            except ssl.SSLEOFError as error:
                if trace.identity_observation:
                    self.record_identity_handshake_error(error)
                    return
                if not self.server.bind_carriers or binding is None:
                    raise
                # Retain the actual error and index. This is NOT accepted here;
                # an independent native typed-cancel/nonce/HTTP0/close proof
                # must authorize this exact server peer at the flush fence.
                with trace.lock:
                    index = len(trace.errors); trace.errors.append(str(error))
                    trace.handshake_eofs.append({**binding, "errorIndex": index, "errorType": "ssl.SSLEOFError",
                                                "authenticated": False, "httpPayloadBytes": 0})
                    trace.event_locked("unverified-bound-handshake-eof", **binding, errorIndex=index)
                return
            except ssl.SSLError as error:
                if trace.identity_observation:
                    if self.server.identity_failure:
                        with trace.lock:
                            trace.rejected.append(self.server.label)
                    self.record_identity_handshake_error(error)
                    return
                if not self.server.identity_failure:
                    raise
                with trace.lock:
                    trace.rejected.append(self.server.label)
                    trace.event_locked("tls-identity-rejected", provider=self.server.label)
                return
            with peer:
                with trace.lock:
                    trace.tls_ready.append((self.server.label, self.client_address))
                    trace.event_locked("tls-handshake-ready", provider=self.server.label,
                                       alpn=peer.selected_alpn_protocol(), peer=self.client_address,
                                       handshakeMilliseconds=round((time.monotonic() - handshake_started) * 1000, 3))
                if peer.selected_alpn_protocol() != "http/1.1":
                    raise AssertionError("HTTPS fixture did not negotiate its fixed HTTP/1.1 ALPN")
                if self.server.identity_failure:
                    raise AssertionError("Trusted certificate with wrong IP SAN was accepted")
                if preflight_carrier:
                    if self.server.label != self.server.preflight_provider:
                        raise AssertionError("Empty TLS preflight used an unapproved provider")
                    # A client TLS-ready callback may precede receipt of its
                    # Finished by this server. This bounded authenticated byte
                    # marker proves that wrap_socket completed before the
                    # client cancels its deliberately DNS/HTTP-empty carrier.
                    peer.sendall(SOURCE_SCOPE_PREFLIGHT_ACK)
                    with trace.lock:
                        trace.preflight_acknowledgements.append((
                            self.server.label, self.client_address, SOURCE_SCOPE_PREFLIGHT_ACK.hex()))
                        trace.event_locked("tls-preflight-ack-sent", provider=self.server.label,
                                           peer=self.client_address, bytes=len(SOURCE_SCOPE_PREFLIGHT_ACK))
                buffered = bytearray()
                while True:
                    while b"\r\n\r\n" not in buffered:
                        data = peer.recv(4096)
                        if not data:
                            if buffered:
                                raise AssertionError("Truncated HTTPS fixture headers")
                            return
                        buffered.extend(data)
                        if len(buffered) > 16_384:
                            raise AssertionError("Unbounded HTTPS fixture headers")
                    header, remainder = bytes(buffered).split(b"\r\n\r\n", 1)
                    buffered = bytearray(remainder)
                    lines = header.decode("ascii").split("\r\n")
                    if lines.pop(0) != "POST /dns-query HTTP/1.1":
                        raise AssertionError("Unexpected HTTPS fixture method/path")
                    fields = {}
                    for line in lines:
                        key, value = line.split(":", 1); key = key.lower()
                        if key in fields:
                            raise AssertionError("Duplicate HTTPS fixture header")
                        fields[key] = value.strip()
                    size = int(fields.get("content-length", "0"))
                    if not 12 <= size <= 65_535 or "transfer-encoding" in fields:
                        raise AssertionError("Invalid HTTPS fixture framing")
                    if fields.get("content-type") != "application/dns-message" or fields.get("host") != self.server.authority:
                        raise AssertionError("HTTPS fixture identity/content type changed")
                    while len(buffered) < size:
                        data = peer.recv(min(4096, size - len(buffered)))
                        if not data:
                            raise AssertionError("Truncated HTTPS fixture DNS body")
                        buffered.extend(data)
                    query = bytes(buffered[:size]); del buffered[:size]
                    name, response = answer(query, self.server.address, source_scope=self.server.source_scope)
                    delay = self.server.query_delays.get(name, self.server.delay)
                    with trace.lock:
                        trace.queries.append((self.server.label, name))
                        trace.query_peers.append((self.server.label, name, self.client_address))
                        trace.query_details.append((self.server.label, name, int.from_bytes(query[:2], "big"), self.client_address))
                        trace.wire_active += 1; trace.wire_peak = max(trace.wire_peak, trace.wire_active)
                        active_question = True
                        trace.event_locked("https-query", provider=self.server.label, name=name,
                                           queryID=f"0x{int.from_bytes(query[:2], 'big'):04x}",
                                           answerAddress=self.server.address, delaySeconds=delay,
                                           peer=self.client_address)
                    time.sleep(delay)
                    headers = ("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
                               f"Content-Length: {len(response)}\r\nConnection: keep-alive\r\n\r\n").encode("ascii")
                    peer.sendall(headers + response)
                    with trace.lock:
                        trace.response_details.append((self.server.label, name, int.from_bytes(query[:2], "big"), self.client_address))
                        trace.wire_active -= 1; active_question = False
                        trace.event_locked("https-answer-sent", provider=self.server.label, name=name,
                                           queryID=f"0x{int.from_bytes(query[:2], 'big'):04x}",
                                           answerAddress=self.server.address)
        except (ConnectionResetError, BrokenPipeError):
            # Flush/client teardown may reset an otherwise clean idle stream.
            with trace.lock:
                trace.event_locked("https-client-teardown", provider=self.server.label)
            return
        except (AssertionError, OSError, UnicodeError, ValueError) as error:
            with trace.lock:
                trace.errors.append(str(error))
                trace.event_locked("https-error", provider=self.server.label, error=str(error)[:512])
        finally:
            with trace.lock:
                if active_question:
                    trace.wire_active -= 1
                trace.tls_active -= 1
                trace.tls_closed.append((self.server.label, self.client_address))
                trace.event_locked("tls-handler-closed", provider=self.server.label, peer=self.client_address)

    def record_identity_handshake_error(self, error: ssl.SSLError) -> None:
        # Preserve every original error. No authorization happens here: only
        # exact client certificate metadata/random/peer proof may cover it.
        trace = self.server.trace
        with trace.lock:
            index = len(trace.errors); trace.errors.append(str(error))
            evidence = {"provider": self.server.label, "peer": self.client_address, "phase": "tls-handshake",
                        "errorType": f"{type(error).__module__}.{type(error).__name__}",
                        "actualSSLError": isinstance(error, ssl.SSLError), "authenticated": False, "errorIndex": index}
            if len(trace.identity_ssl_errors) < 128:
                trace.identity_ssl_errors.append(evidence)
            trace.event_locked("identity-handshake-error", **evidence)


def read_identity_certificate_artifact(path: Path) -> bytes:
    """Identity-only public certificate evidence from its private fixed file."""
    properties = path.lstat()
    if (not stat.S_ISREG(properties.st_mode) or stat.S_IMODE(properties.st_mode) != 0o600
            or not 1 <= properties.st_size <= 16_384 or path.resolve() != path):
        raise AssertionError("Identity certificate must be a bounded private regular artifact")
    with path.open("rb") as artifact:
        opened = os.fstat(artifact.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mode) != \
                (properties.st_dev, properties.st_ino, properties.st_size, properties.st_mode):
            raise AssertionError("Identity certificate artifact changed before its actual read")
        contents = artifact.read(16_385)
    after = path.lstat()
    if (len(contents) != properties.st_size or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) !=
            (properties.st_dev, properties.st_ino, properties.st_size, properties.st_mtime_ns)):
        raise AssertionError("Identity certificate artifact changed during its actual read")
    return contents


def identity_pem_der(contents: bytes) -> bytes:
    """Hash the sole actual loaded leaf, never a label or a guessed digest."""
    try:
        pem = contents.decode("ascii").strip()
        if re.fullmatch(r"-----BEGIN CERTIFICATE-----\r?\n(?:[A-Za-z0-9+/=]+\r?\n)+-----END CERTIFICATE-----", pem) is None:
            raise ValueError("Not the fixed single-certificate PEM artifact")
        der = ssl.PEM_cert_to_DER_cert(pem)
    except (ValueError, UnicodeError) as error:
        raise AssertionError("Identity evidence is not the actual loaded single PEM certificate") from error
    if not 1 <= len(der) <= 16_384:
        raise AssertionError("Identity certificate DER exceeded its unchanged private bound")
    return der


class TLSService(HandlerDrainTracker, socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, trace: Trace, label: str, *, certificate: Path | None = None,
                 key: Path | None = None, delay: float = 0, identity_failure: bool = False,
                 source_scope: bool = False, preflight_provider: str = "first", bind_carriers: bool = False,
                 query_delays: dict[str, float] | None = None) -> None:
        self.trace, self.label = trace, label
        self.delay, self.identity_failure = delay, identity_failure
        self.query_delays = dict(query_delays or {})
        self.source_scope = source_scope
        self.bind_carriers = bind_carriers
        self.preflight_provider = preflight_provider
        self.identity_leaf_sha256: str | None = None
        if source_scope:
            self.request_queue_size = 64  # Bounded fixture backlog, not an application quota change.
        self.address = "203.0.113.80" if label == "first" else "203.0.113.81"
        if certificate is not None:
            identity_pem = read_identity_certificate_artifact(certificate) if trace.identity_observation else None
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.context.minimum_version = ssl.TLSVersion.TLSv1_2
            self.context.set_alpn_protocols(["http/1.1"])
            self.context.load_cert_chain(certificate, key)
            if identity_pem is not None:
                if read_identity_certificate_artifact(certificate) != identity_pem:
                    raise AssertionError("Identity leaf bytes changed across the actual SSLContext load")
                self.identity_leaf_sha256 = hashlib.sha256(identity_pem_der(identity_pem)).hexdigest()
        super().__init__(("127.0.0.1", 0), HealthyTLS if certificate is not None else RejectTLS)
        self.authority = f"127.0.0.1:{self.server_address[1]}"


class DNSService(HandlerDrainTracker, socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, trace: Trace, *, excluded_ports: tuple[int, ...] = ()) -> None:
        self.trace = trace
        for _ in range(16):
            super().__init__(("127.0.0.1", 0), PlainDNS)
            if self.server_address[1] not in excluded_ports:
                return
            self.server_close()
        raise AssertionError("Cannot allocate a distinct unused traditional UDP port")


def capture_forwarded_client_hello(prefix: bytearray, payload, written: int, trace: Trace, observation: dict) -> None:
    """Call only after a successful upstream send; copy no more than 43 bytes."""
    if not 0 <= len(prefix) < CLIENT_HELLO_PREFIX_BYTES or type(written) is not int or not 0 < written <= len(payload):
        raise AssertionError("ClientHello capture is not an actual positive socket write receipt")
    prefix.extend(payload[:min(written, CLIENT_HELLO_PREFIX_BYTES - len(prefix))])
    with trace.lock:
        observation["helloForwardedBytes"] = len(prefix)
        observation["helloPrefixHex"] = prefix.hex()


def relay(client: socket.socket, upstream: socket.socket, initial: bytes, *, identity_capture=None) -> None:
    """Opaque bounded forwarding, including pending bytes before TCP half-close."""
    limit = 256 * 1024
    other = {client: upstream, upstream: client}
    buffers = {client: bytearray(), upstream: bytearray(initial)}
    readable = {client: True, upstream: True}
    closed_write: set[socket.socket] = set()
    deadline = time.monotonic() + 10
    client.setblocking(False); upstream.setblocking(False)
    hello_prefix = bytearray() if identity_capture is not None else None
    with selectors.DefaultSelector() as selector:
        while readable[client] or readable[upstream] or buffers[client] or buffers[upstream]:
            for peer in (client, upstream):
                destination = other[peer]
                if not readable[destination] and not buffers[peer] and peer not in closed_write:
                    try:
                        peer.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass  # Teardown may already have closed this write side.
                    closed_write.add(peer)
                events = (selectors.EVENT_READ if readable[peer] and len(buffers[destination]) < limit else 0)
                if buffers[peer]:
                    events |= selectors.EVENT_WRITE
                try:
                    registered = selector.get_key(peer)
                except KeyError:
                    if events:
                        selector.register(peer, events)
                else:
                    if events:
                        if registered.events != events:
                            selector.modify(peer, events)
                    else:
                        selector.unregister(peer)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError("Loopback CONNECT relay exceeded its bounded idle deadline")
            for key, events in selector.select(min(remaining, 0.5)):
                peer, destination = key.fileobj, other[key.fileobj]
                if events & selectors.EVENT_READ:
                    try:
                        payload = peer.recv(min(16_384, limit - len(buffers[destination])))
                    except BlockingIOError:
                        payload = None
                    if payload is not None:
                        if payload:
                            buffers[destination].extend(payload); deadline = time.monotonic() + 10
                        else:
                            readable[peer] = False
                if events & selectors.EVENT_WRITE and buffers[peer]:
                    try:
                        sent = peer.send(buffers[peer])
                    except BlockingIOError:
                        sent = 0
                    if sent:
                        if peer is upstream and hello_prefix is not None and len(hello_prefix) < CLIENT_HELLO_PREFIX_BYTES:
                            # Observe only bytes actually accepted by this
                            # upstream socket write, before deleting them.
                            trace, observation = identity_capture
                            capture_forwarded_client_hello(hello_prefix, memoryview(buffers[peer]), sent, trace, observation)
                        del buffers[peer][:sent]; deadline = time.monotonic() + 10


class CONNECT(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        trace: Trace = self.server.trace
        with trace.lock:
            observation = {"ordinal": len(trace.proxy_connections), "peer": self.client_address,
                           "proxyEndpoint": self.server.server_address,
                           "acceptedSeconds": round(time.monotonic() - trace.started, 6),
                           "receivedBytes": 0, "cleanEOF": False, "connectHeaderComplete": False,
                           "upstreamOpened": False, "targetPort": None}
            trace.proxy_connections.append(observation)
            trace.proxy_peers.append(self.client_address[0])
            trace.event_locked("proxy-handler-start", peer=self.client_address)
        try:
            if self.client_address[0] != "127.0.0.1":
                raise AssertionError("CONNECT peer must be exactly 127.0.0.1")
            self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.request.settimeout(5)
            buffered = bytearray()
            while b"\r\n\r\n" not in buffered:
                payload = self.request.recv(min(4096, 16_385 - len(buffered)))
                if not payload:
                    with trace.lock:
                        observation["cleanEOF"] = True
                    if not buffered:
                        with trace.lock:
                            observation["preConnectEmptyEOF"] = True
                            trace.event_locked("proxy-empty-clean-eof", peer=self.client_address,
                                               receivedBytes=0, upstreamOpened=False)
                        return  # Classification is decided by the strict parent ledger, not this handler.
                    raise AssertionError("Truncated CONNECT request")
                buffered.extend(payload)
                with trace.lock:
                    observation["receivedBytes"] = len(buffered)
                if len(buffered) > 16_384:
                    raise AssertionError("Unbounded CONNECT headers")
            header, initial = bytes(buffered).split(b"\r\n\r\n", 1)
            with trace.lock:
                observation["connectHeaderComplete"] = True
            lines = header.decode("ascii").split("\r\n")
            request = lines.pop(0).split(" ")
            if len(request) != 3 or request[0] != "CONNECT" or request[2] != "HTTP/1.1":
                raise AssertionError("Loopback proxy only accepts literal CONNECT requests")
            authority = request[1]
            if authority not in self.server.authorities:
                raise AssertionError("CONNECT target escaped its approved literal-loopback TLS ports")
            fields = {}
            for line in lines:
                if ":" not in line or "\n" in line or "\r" in line:
                    raise AssertionError("Malformed CONNECT header")
                name, value = line.split(":", 1); name = name.lower()
                if name not in {"host", "proxy-connection", "connection"} or name in fields:
                    raise AssertionError("CONNECT fixture cannot accept credentials, duplicate or extra headers")
                fields[name] = value.strip()
            if fields.get("host") != authority:
                raise AssertionError("CONNECT authority and Host identity differ")
            # Membership was checked before socket construction. Never resolve
            # or connect a hostname from the request, even a loopback alias.
            port = self.server.authorities[authority]
            with trace.lock:
                observation["targetPort"] = port
                trace.connects.append(("127.0.0.1", port))
                trace.event_locked("connect-admitted", authority=authority, port=port)
            if port in self.server.failure_ports:
                # An explicitly injected, framed transport outage, not a
                # REJECT/authentication error and not an ignored SSL failure.
                # Never create the upstream socket for this first provider.
                self.request.sendall(b"HTTP/1.1 503 Fixture outage\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                with trace.lock:
                    trace.connect_failures.append(("127.0.0.1", port, 503))
                    trace.event_locked("connect-fixture-outage", port=port, status=503)
                return
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as upstream:
                upstream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                upstream.settimeout(5)
                upstream.connect(("127.0.0.1", port))
                with trace.lock:
                    observation["upstreamOpened"] = True
                self.request.sendall(b"HTTP/1.1 200 Connected\r\n\r\n")
                with trace.lock:
                    trace.event_locked("connect-ready", authority=authority, port=port,
                                       proxyPeer=self.client_address, tlsPeer=upstream.getsockname())
                    if trace.identity_observation and observation["ordinal"] < 128:
                        observation.update({"identityCapture": True, "tlsPeer": upstream.getsockname(),
                                            "identityProvider": self.server.identity_provider_by_port[port],
                                            "helloForwardedBytes": 0, "helloPrefixHex": ""})
                capture = (trace, observation) if observation.get("identityCapture") is True else None
                relay(self.request, upstream, initial, identity_capture=capture)
        except (ConnectionResetError, BrokenPipeError):
            with trace.lock:
                trace.event_locked("proxy-client-teardown")
            return  # Flush/client cancellation may close an idle TLS carrier.
        except (AssertionError, UnicodeError, ValueError) as error:
            with trace.lock:
                trace.proxy_rejected.append(str(error))
                trace.event_locked("proxy-rejected", error=str(error)[:512])
            try:
                self.request.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
        except OSError as error:
            with trace.lock:
                trace.errors.append(f"CONNECT relay: {error}")
                trace.event_locked("proxy-error", error=str(error)[:512])
        finally:
            with trace.lock:
                observation["closedSeconds"] = round(time.monotonic() - trace.started, 6)


class CONNECTService(HandlerDrainTracker, socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, trace: Trace, tls_ports: tuple[int, int], *, excluded_ports: tuple[int, ...],
                 source_scope: bool = False, multi_upstream: bool = False,
                 first_connect_failure: bool = False) -> None:
        if len(set(tls_ports)) != 2 or any(not 0 < port <= 65_535 for port in tls_ports):
            raise AssertionError("CONNECT requires two distinct bounded TLS ports")
        self.trace = trace
        self.identity_provider_by_port = dict(zip(tls_ports, ("first", "second"))) if trace.identity_observation else {}
        if source_scope or multi_upstream:
            self.request_queue_size = 64
        # Keep both server ports disjoint and monitored, but approve only the
        # first in the source-pool component test. Other adaptive scenarios
        # retain the original two-provider CONNECT authority set.
        admitted_ports = tls_ports[:1] if source_scope else tls_ports
        self.authorities = {f"127.0.0.1:{port}": port for port in admitted_ports}
        self.failure_ports = {tls_ports[0]} if first_connect_failure else set()
        excluded = set(excluded_ports) | set(tls_ports)
        for _ in range(16):
            super().__init__(("127.0.0.1", 0), CONNECT)
            if self.server_address[1] not in excluded:
                with trace.lock:
                    trace.approved_proxy_endpoint = self.server_address
                return
            self.server_close()
        raise AssertionError("Cannot allocate a distinct loopback HTTP proxy port")


@contextmanager
def running(server):
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)


def certificates(directory: Path) -> tuple[Path, Path, Path]:
    """Create private, one-day EC test artifacts without touching any keychain."""
    ca_config = directory / "ca.cnf"
    ca_config.write_text(
        "[req]\ndistinguished_name = dn\nx509_extensions = ca\nprompt = no\n"
        "[dn]\nCN = Hajimi Ephemeral DNS Fixture CA\n"
        "[ca]\nbasicConstraints = critical,CA:true\nkeyUsage = critical,keyCertSign,cRLSign\n"
        "subjectKeyIdentifier = hash\n", encoding="ascii")
    ca_config.chmod(0o600)

    def openssl(*arguments: str) -> None:
        result = subprocess.run(("/usr/bin/openssl", *arguments), text=True, capture_output=True,
                                timeout=15, check=False)
        if result.returncode:
            raise AssertionError(f"Local temporary certificate generation failed: {result.stderr.strip()}")

    ca_key, ca_pem = directory / "ca.key", directory / "ca.pem"
    openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(ca_key))
    ca_key.chmod(0o600)
    openssl("req", "-new", "-x509", "-sha256", "-key", str(ca_key), "-days", "1",
            "-config", str(ca_config), "-out", str(ca_pem))
    openssl("x509", "-in", str(ca_pem), "-outform", "DER", "-out", str(directory / "ca.der"))
    key = directory / "server.key"
    openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key))
    key.chmod(0o600)
    request = directory / "server.csr"
    openssl("req", "-new", "-sha256", "-key", str(key), "-subj", "/CN=unused.fixture.example.test",
            "-config", str(ca_config), "-out", str(request))
    for serial, (label, san) in enumerate((("good", "127.0.0.1"), ("wrong-san", "127.0.0.2")), 1):
        extension = directory / f"{label}.cnf"
        extension.write_text(
            "[leaf]\nbasicConstraints = critical,CA:false\nkeyUsage = critical,digitalSignature\n"
            f"extendedKeyUsage = serverAuth\nsubjectAltName = IP:{san}\n"
            "subjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid,issuer\n", encoding="ascii")
        extension.chmod(0o600)
        openssl("x509", "-req", "-sha256", "-in", str(request), "-CA", str(ca_pem),
                "-CAkey", str(ca_key), "-set_serial", str(serial), "-days", "1",
                "-extfile", str(extension), "-extensions", "leaf", "-out", str(directory / f"{label}.pem"))
    for artifact in directory.iterdir():
        if artifact.is_file():
            artifact.chmod(0o600)
    return directory / "good.pem", directory / "wrong-san.pem", key


def read_private_json(path: Path, *, maximum_bytes: int = 4096) -> dict:
    properties = path.lstat()
    if (not stat.S_ISREG(properties.st_mode) or stat.S_IMODE(properties.st_mode) != 0o600
            or not 1 <= properties.st_size <= maximum_bytes or path.resolve() != path):
        raise AssertionError("Source-scope flush fence must be a bounded private regular artifact")
    try:
        value = json.loads(path.read_bytes())
    except (ValueError, UnicodeError) as error:
        raise AssertionError("Source-scope flush fence is not its complete JSON artifact") from error
    if not isinstance(value, dict):
        raise AssertionError("Source-scope flush fence must be its fixed JSON object")
    return value


def run_source_scope_cli(command: tuple[str, ...], environment: dict, root: Path, trace: Trace,
                         first, second, proxy, *, multi_upstream: bool = False) -> subprocess.CompletedProcess:
    """Drain child pipes concurrently while fencing real server socket close.

    No IPC control socket, user profile or global network state is involved.
    The child pauses between epochs using two bounded, mode-0600 files inside
    its already-admitted private temporary root. A cancel request alone never
    earns the close ACK; all TLS/CONNECT handlers must physically finish first.
    """
    prefix = "multi-upstream" if multi_upstream else "source-scope"
    ready = root / f"{prefix}-flush.ready.json"
    acknowledgement = root / f"{prefix}-flush.ack.json"
    if ready.exists() or acknowledgement.exists():
        raise AssertionError("Source-scope child cannot inherit a previous flush fence")
    process = subprocess.Popen(command, env=environment, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
    completed = threading.Event()
    communication: dict = {}
    timeout = 55

    def communicate() -> None:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            communication["result"] = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
        except subprocess.TimeoutExpired as error:
            process.kill()
            stdout, stderr = process.communicate()
            error.output, error.stderr = stdout, stderr
            communication["error"] = error
        finally:
            completed.set()

    reader = threading.Thread(target=communicate, daemon=True)
    reader.start()
    deadline = time.monotonic() + timeout
    try:
        while not ready.exists() and not completed.is_set() and time.monotonic() < deadline:
            completed.wait(0.005)
        if not ready.exists():
            if completed.is_set() and "result" in communication:
                return communication["result"]  # Preserve an early Core diagnostic, not a success allowance.
            raise subprocess.TimeoutExpired(command, timeout)
        child = read_private_json(ready)
        interrupted = child.get("typedTLSCancelled", 0) if multi_upstream else 0
        if (child.get("version") != 1 or child.get("phase") != "flush-ready"
                or child.get("logicalActive") != 0 or child.get("logicalPending") != 0
                or not isinstance(child.get("rawReady"), int) or not 2 <= child["rawReady"] <= 65
                or type(interrupted) is not int or interrupted < 0
                or child.get("tlsReady", -1) + interrupted != child["rawReady"]
                or child.get("cancelRequests") != child["tlsReady"]
                or (multi_upstream and child.get("preludeFailures") != 0)
                or (not 352 <= child.get("clientHTTPQueries", 0) <= 704 if multi_upstream
                    else child.get("clientHTTPQueries") != 352)):
            raise AssertionError("Child flush fence did not revoke old logical/TLS owners")
        with trace.lock:
            trace.event_locked("source-flush-close-wait", expectedOldCarriers=child["rawReady"])
        # Relay drain comes first, then TLS. An admitted but not-yet-started
        # worker cannot be hidden by a snapshot of active handlers == zero.
        for service in (proxy, first, second):
            if service is None or not service.wait_idle():
                raise AssertionError("Source flush did not close every old physical CONNECT/TLS carrier")
        with proxy._drain:
            proxy_active = proxy._active_handlers
        if multi_upstream:
            proof = read_private_json(root / "multi-upstream-carriers.proof.json", maximum_bytes=16_384)
            with trace.lock: trace.carrier_proof = proof
            validate_bound_carrier_peers(trace.snapshot(), proof)
        with trace.lock:
            old = {"version": 1, "phase": "flush-closed", "tlsStarted": len(trace.tls_peers),
                   "tlsReady": len(trace.tls_ready), "tlsClosed": len(trace.tls_closed),
                   "tlsHandlersActive": trace.tls_active, "connectHandlersActive": proxy_active,
                   "traditionalQueries": trace.plaintext, "clientHTTPQueries": child["clientHTTPQueries"],
                   "serverQuestions": len(trace.query_details), "serverAnswers": len(trace.response_details),
                   "connectAttempts": len(trace.connects), "connectFailures": len(trace.connect_failures),
                   "closedPeers": list(trace.tls_closed)}
            ready_agrees = child["tlsReady"] <= old["tlsReady"] <= child["rawReady"] if multi_upstream else old["tlsReady"] == child["tlsReady"]
            if (old["tlsStarted"] != child["rawReady"] or not ready_agrees
                    or old["tlsClosed"] != old["tlsStarted"] or old["tlsHandlersActive"] != 0
                    or proxy_active != 0 or trace.wire_active != 0 or trace.plaintext != 0
                    or trace.rejected or trace.proxy_rejected or (trace.errors and not multi_upstream)
                    or old["serverQuestions"] != child["clientHTTPQueries"] or old["serverAnswers"] != child["clientHTTPQueries"]):
                raise AssertionError("Server-side physical flush witness disagrees with the child owners/wire ledger")
            trace.scope_checkpoints.append(old)
            trace.event_locked("source-flush-all-physical-closed", tlsCarriers=old["tlsClosed"], queries=old["serverQuestions"])
        pending = root / f"{prefix}-flush.ack.pending.json"
        descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii") as output:
            json.dump(old, output, sort_keys=True)
        pending.replace(acknowledgement)
        if not completed.wait(max(0, deadline - time.monotonic())):
            raise subprocess.TimeoutExpired(command, timeout)
        if "error" in communication:
            raise communication["error"]
        return communication["result"]
    finally:
        if process.poll() is None:
            process.kill()
        completed.wait(3)
        reader.join(timeout=3)


def validate_source_scope_cli_output(details: str, *, multi_upstream: bool = False,
                                    scenario: str = "source-scope-burst") -> dict:
    def marker(name: str) -> dict:
        rows = [line[len(name) + 1:] for line in details.splitlines() if line.startswith(name + " ")]
        if len(rows) != 1:
            raise AssertionError(f"Source-scope child must publish exactly one {name} observation")
        try:
            value = json.loads(rows[0])
        except (ValueError, UnicodeError) as error:
            raise AssertionError("Source-scope child emitted an incomplete counter object") from error
        if not isinstance(value, dict):
            raise AssertionError("Source-scope counter observation must be a JSON object")
        return value

    prefix = "DNS-MULTI-UPSTREAM" if multi_upstream else "DNS-SOURCE-SCOPE"
    logical = marker(prefix + "-LOGICAL")
    physical = marker(prefix + "-PHYSICAL")
    flushed = marker(prefix + "-FLUSH")
    for value, names in ((logical, ("queries", "completedClients", "upstreamLeaders", "mergedClients", "cacheHits",
                                   "logicalActivePeak", "logicalQueuedPeak", "logicalWaitingClientsPeak", "activeLimit",
                                   "leaderCapacity", "failures", "capacityFailures", "timeoutFailures", "perQueryDeadlineMilliseconds")),
                         (physical, ("approvedEncryptedProviders", "preflightRawReady", "preflightTLSReady", "preflightDNSQueries",
                                     "preflightAcknowledgementBytes", "dnsRawCarrierReady",
                                     "dnsTLSReady", "tlsFailures", "clientHTTPQueries", "encryptedConnectionReuse")),
                         (flushed, ("oldTLSCarriersClosedByServer", "newEpochRawCarriers", "newEpochWireQueries",
                                    "logicalActive", "logicalPending"))):
        if any(type(value.get(name)) is not int for name in names):
            raise AssertionError("Source-scope counters must retain integer measurements, not missing/string/bool values")
    if type(logical.get("maximumSuccessfulMilliseconds")) not in {int, float}:
        raise AssertionError("Source-scope elapsed time must be a numeric measurement")
    if multi_upstream and any(type(physical.get(name)) is not int for name in ("typedTLSCancelled", "preludeFailures")):
        raise AssertionError("Native/prelude counters must be explicit integers")
    if (logical.get("queries") != 449 or logical.get("completedClients") != 450
            or logical.get("upstreamLeaders") != 352 or logical.get("mergedClients") != 96
            or logical.get("cacheHits") != 1 or logical.get("logicalActivePeak") != 16
            or not 1 <= logical.get("logicalQueuedPeak", 0) <= 512
            or not 1 <= logical.get("logicalWaitingClientsPeak", 0) <= 512
            or logical.get("activeLimit") != 16 or logical.get("leaderCapacity") != 512
            or logical.get("failures") != 0 or logical.get("capacityFailures") != 0
            or logical.get("timeoutFailures") != 0 or logical.get("perQueryDeadlineMilliseconds") != 8000
            or not 0 < logical.get("maximumSuccessfulMilliseconds", 8000) < 8000):
        raise AssertionError("Actual logical governor observations failed bounded admission/cache/ID/deadline checks")
    if (physical.get("approvedEncryptedProviders") != (2 if multi_upstream else 1)
            or physical.get("preflightRawReady") != 1 or physical.get("preflightTLSReady") != 1
            or physical.get("preflightDNSQueries") != 0
            or physical.get("preflightAcknowledgementBytes") != len(SOURCE_SCOPE_PREFLIGHT_ACK)
            or physical.get("preflightAuthenticatedACK") is not True
            or not 1 <= physical.get("dnsRawCarrierReady", 0) <= 64
            or physical.get("dnsTLSReady") + (physical.get("typedTLSCancelled", 0) if multi_upstream else 0) != physical.get("dnsRawCarrierReady")
            or physical.get("tlsFailures") != 0
            or (not 352 <= physical.get("clientHTTPQueries", 0) <= 704 if multi_upstream
                else physical.get("clientHTTPQueries") != 352)
            or physical.get("encryptedConnectionReuse", 0) < 288):
        raise AssertionError("Actual routed raw/TLS/reuse observations still amplify source scopes")
    if multi_upstream:
        if (type(physical.get("typedTLSCancelled")) is not int or physical["typedTLSCancelled"] < 0
                or physical.get("preludeFailures") != 0 or type(logical.get("upstreamAttempts")) is not int
                or not 352 <= logical["upstreamAttempts"] <= 352 * 3):
            raise AssertionError("Multi-provider native phases or original maximum-three attempt budget changed")
        if type(logical.get("failovers")) is not int or logical["failovers"] <= 0:
            raise AssertionError("Multi-upstream pressure never exercised a real approved second attempt")
        if scenario == "multi-upstream-burst" and (
                type(physical.get("delayedTLSCallbacks")) is not int or physical["delayedTLSCallbacks"] <= 0
                or type(physical.get("lateCancelledTLSCallbacks")) is not int
                or physical["lateCancelledTLSCallbacks"] <= 0):
            raise AssertionError("Slow-carrier pressure did not retain/deliver genuine TLS callbacks after cancellation")
    fresh_carriers = 2 if scenario == "multi-upstream-burst" else 1
    if (flushed.get("oldTLSCarriersClosedByServer") != physical["dnsRawCarrierReady"] + 1
            or flushed.get("newEpochRawCarriers") != fresh_carriers
            or (not 1 <= flushed.get("newEpochWireQueries", 0) <= 2 if multi_upstream else flushed.get("newEpochWireQueries") != 1)
            or flushed.get("serverCloseFence") is not True
            or flushed.get("logicalActive") != 0 or flushed.get("logicalPending") != 0):
        raise AssertionError("Flush reused an old cache/physical carrier or its close fence was only a logical cancel")
    answers = marker(prefix + "-ANSWERS") if multi_upstream else None
    if multi_upstream and (answers.get("fixtureOnly") is not True or not isinstance(answers.get("replyAddresses"), list)):
        raise AssertionError("Multi-upstream client answers must be an explicit fixture-only transaction ledger")
    proof = marker(prefix + "-CARRIERS") if multi_upstream else None
    if multi_upstream:
        records = parse_carrier_proof(proof)
        if (proof["rawReady"] != physical["preflightRawReady"] + physical["dnsRawCarrierReady"] + fresh_carriers
                or proof["typedTLSCancelled"] < physical["typedTLSCancelled"]
                or sum(row["httpQueries"] for row in records.values()) != physical["clientHTTPQueries"] + flushed["newEpochWireQueries"]):
            raise AssertionError("Complete native carrier proof lost raw/HTTP/fresh-epoch ownership")
    return {"logical": logical, "physical": physical, "flush": flushed, "answers": answers, "carrierProof": proof}


def run(binary: Path, protection: bool, scenario: str) -> None:
    source_scope = scenario == "source-scope-burst"
    multi_upstream = scenario in MULTI_UPSTREAM_SCENARIOS
    pressure = source_scope or multi_upstream
    connect_failure = scenario == "multi-upstream-connect-failure-burst"
    trace = Trace(maximum_events=4096 if pressure else 256)
    trace.identity_observation = scenario == IDENTITY_SCENARIO
    production = scenario in {"production-success", "production-identity-failure", "source-scope-burst"} or multi_upstream
    base_scenario = scenario.removeprefix("production-") if production else scenario
    with failure_trace(trace, protection, scenario), \
            tempfile.TemporaryDirectory(prefix="hajimi-dns-adaptive-") as directory, ExitStack() as stack:
        root = Path(directory).resolve(); root.chmod(0o700)
        home = root / "home"; home.mkdir(mode=0o700)
        identity_ca_der: bytes | None = None
        identity_ca_sha256: str | None = None
        if base_scenario == "failure":
            first_service, second_service = TLSService(trace, "first"), TLSService(trace, "second")
        else:
            good, wrong, key = certificates(root)
            if trace.identity_observation:
                identity_ca_der = read_identity_certificate_artifact(root / "ca.der")
                if identity_pem_der(read_identity_certificate_artifact(root / "ca.pem")) != identity_ca_der:
                    raise AssertionError("Actual child DER anchor is not the independently generated fixture CA")
                identity_ca_sha256 = hashlib.sha256(identity_ca_der).hexdigest()
            first_service = TLSService(trace, "first", certificate=wrong if base_scenario == "identity-failure" else good,
                                       key=key, delay=0.025 if pressure else 0.55,
                                       identity_failure=base_scenario == "identity-failure", source_scope=pressure,
                                       preflight_provider="second" if connect_failure else "first", bind_carriers=multi_upstream,
                                       # One cold success does not spend an exploration opportunity.
                                       # Make this real question slow enough for the normal RTT hedge
                                       # to discover the independently authenticated faster provider.
                                       query_delays={"adaptive.discover.example.test": 1.3} if base_scenario == "success" else None)
            second_service = TLSService(trace, "second", certificate=good, key=key,
                                        delay=0.025 if pressure else 0.02, source_scope=pressure,
                                        preflight_provider="second" if connect_failure else "first", bind_carriers=multi_upstream)
        first = stack.enter_context(running(first_service))
        second = stack.enter_context(running(second_service))
        tls_ports = (first.server_address[1], second.server_address[1])
        plain = stack.enter_context(running(DNSService(trace, excluded_ports=tls_ports)))
        proxy = stack.enter_context(running(CONNECTService(trace, tls_ports,
            excluded_ports=(*tls_ports, plain.server_address[1]), source_scope=source_scope,
            multi_upstream=multi_upstream, first_connect_failure=connect_failure))) if production else None
        ports = (*tls_ports, plain.server_address[1], *((proxy.server_address[1],) if proxy else ()))
        if len(set(ports)) != len(ports):
            raise AssertionError("All TLS, unused traditional and HTTP proxy ports must be distinct")
        with trace.lock:
            trace.providers = [{"provider": peer.label, "authority": peer.authority, "answerAddress": peer.address,
                                "delaySeconds": peer.delay, "identityFailure": peer.identity_failure}
                               for peer in (first_service, second_service)]
            if trace.identity_observation:
                for entry, peer in zip(trace.providers, (first_service, second_service)):
                    entry.update({"loadedLeafSHA256": peer.identity_leaf_sha256, "fixtureAnchorSHA256": identity_ca_sha256})
        profile = root / "fixture.conf"
        profile_text = (
            f"[General]\ndns-leak-protection = {str(protection).lower()}\nfake-ip = false\n"
            f"dns-server = 127.0.0.1:{plain.server_address[1]}\n"
            f"encrypted-dns-server = https://127.0.0.1:{first.server_address[1]}/dns-query"
            + (f", https://127.0.0.1:{second.server_address[1]}/dns-query" if not source_scope else "") + "\n"
            + (f"[Proxy]\nLoopbackHTTP = http, 127.0.0.1, {proxy.server_address[1]}\n" if proxy else "")
            + "[Rule]\nDOMAIN,blocked.example.test,REJECT\n"
            + ("SRC-PORT,65535,REJECT\n" if pressure else "")
            + ("FINAL,LoopbackHTTP\n" if proxy else "FINAL,DIRECT\n"))
        profile.write_text(profile_text, encoding="utf-8")
        profile.chmod(0o600)
        environment = os.environ.copy()
        for key in tuple(environment):
            if key.startswith("HAJIMI_TEST_"):
                environment.pop(key)
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                    "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
            environment[key] = ""
        environment.update({"HOME": str(home), "CFFIXED_USER_HOME": str(home), "LANG": "C", "LC_ALL": "C",
                            "TMPDIR": str(root.parent) + os.sep})
        if base_scenario == "success":
            # The profile/CLI guard fixes all hosts, policies and credentials.
            # This isolated child-only diagnostic supplies the registered
            # candidate/ordinal ledger; it changes no production setting.
            environment["HAJIMI_NATIVE_DEBUG"] = "1"
        command = (str(binary), "--dns-adaptive-loopback-test", "--dns-adaptive-fixture-root", str(root),
                   "--dns-adaptive-fixture-scenario", scenario)
        with trace.lock:
            trace.event_locked("cli-start", protection=protection, scenario=scenario)
        try:
            result = run_source_scope_cli(command, environment, root, trace, first, second, proxy,
                                          multi_upstream=multi_upstream) if pressure \
                else subprocess.run(command, env=environment,
                                    text=True, capture_output=True, timeout=40, check=False)
        except subprocess.TimeoutExpired as error:
            if pressure:
                stdout = error.output if isinstance(error.output, str) else ""
                stderr = error.stderr if isinstance(error.stderr, str) else ""
                capture_source_scope_timing(stdout + "\n" + stderr, trace, multi_upstream=multi_upstream)
            with trace.lock:
                trace.event_locked("cli-timeout", timeoutSeconds=55 if pressure else 40)
            raise
        with trace.lock:
            trace.event_locked("cli-exit", returnCode=result.returncode)
        if trace.identity_observation:
            try:
                identity_proof = read_private_json(root / "identity-carriers.proof.json", maximum_bytes=16_384)
            except (AssertionError, OSError) as error:
                with trace.lock:
                    trace.event_locked("identity-witness-capture-error", passAuthorization=False,
                                       captureError=type(error).__name__, captureErrorDescriptionForensicsOnly=str(error)[:256])
                if result.returncode == 0:
                    raise
            else:
                with trace.lock:
                    trace.identity_witness = identity_proof
                    trace.event_locked("identity-witness-captured", passAuthorization=False)
        if multi_upstream and result.returncode != 0:
            proof_path = root / "multi-upstream-carriers.proof.json"
            try:
                # Failure-only forensic capture while the admitted private
                # directory still exists. Do NOT parse/authorize cancellation
                # or convert the failed CLI into an oracle success here.
                proof = read_private_json(proof_path, maximum_bytes=16_384)
            except (AssertionError, OSError) as error:
                # Missing/invalid diagnostic evidence must not obscure the
                # original nonzero CLI result or authorize a success either.
                with trace.lock:
                    trace.event_locked("failed-cli-complete-proof-capture-error", passAuthorization=False,
                                       captureError=type(error).__name__,
                                       captureErrorDescriptionForensicsOnly=str(error)[:256])
            else:
                with trace.lock:
                    trace.carrier_proof = proof
                    trace.event_locked("failed-cli-complete-proof-captured", passAuthorization=False)
        if pressure:
            capture_source_scope_timing(result.stdout + "\n" + result.stderr, trace, multi_upstream=multi_upstream)
        details = require_completed_cli(result)
        if trace.identity_observation:
            if read_identity_certificate_artifact(root / "ca.der") != identity_ca_der:
                raise AssertionError("Actual fixture CA DER changed while the child evaluated its trust")
            markers = [line[len(IDENTITY_MARKER):] for line in details.splitlines() if line.startswith(IDENTITY_MARKER)]
            if len(markers) != 1 or len(markers[0].encode()) > 16_384:
                raise AssertionError("Identity CLI/private witness did not retain the same complete bounded proof")
            try:
                marker_proof = json.loads(markers[0])
            except (ValueError, UnicodeError) as error:
                raise AssertionError("Identity CLI marker is not its complete JSON proof") from error
            if marker_proof != trace.identity_witness:
                raise AssertionError("Identity CLI/private witness disagree")
        if base_scenario == "success":
            capture_functional_witness(details, trace, scenario)
        scope_counters = validate_source_scope_cli_output(details, multi_upstream=multi_upstream,
                                                         scenario=scenario) if pressure else None
        if multi_upstream:
            with trace.lock:
                trace.multi_upstream_client_answers = scope_counters["answers"]["replyAddresses"]
                trace.carrier_proof = scope_counters["carrierProof"]
        # The exited child cannot add dials. Drain the relay before TLS peers,
        # so an admitted but not-yet-scheduled worker cannot skew carrier counts.
        for peer in ([proxy] if proxy else []) + [first, second, plain]:
            if not peer.wait_idle():
                raise AssertionError("Adaptive fixture handlers did not drain after CLI completion")
        if proxy:
            with proxy._drain:
                proxy_active = proxy._active_handlers
            with trace.lock:
                trace.proxy_handlers_active = proxy_active
        observed = trace.snapshot()
        speculative = validate_wire_trace(observed, base_scenario, production,
                                          {"first": tls_ports[0], "second": tls_ports[1]})
        if pressure:
            client = scope_counters["physical"]
            fresh = scope_counters["flush"]["newEpochRawCarriers"]
            if ((not multi_upstream and len(observed["tlsReady"]) != client["preflightTLSReady"] + client["dnsTLSReady"] + fresh)
                    or len(observed["connects"]) - len(observed["connectFailures"])
                    != client["preflightRawReady"] + client["dnsRawCarrierReady"] + fresh):
                raise AssertionError("Independent client physical observations and actual server TLS/CONNECT ledger disagree")
        with trace.lock:
            hellos, queries, rejected = list(trace.hellos), list(trace.queries), list(trace.rejected)
            tls_peers = list(trace.tls_peers)
            query_peers = list(trace.query_peers)
            connects, proxy_peers, proxy_rejected = list(trace.connects), list(trace.proxy_peers), list(trace.proxy_rejected)
            plaintext, errors = trace.plaintext, list(trace.errors)
        # This malformed fixture must stop at admission, before dialing even
        # the remaining valid peer. All possible destinations remain loopback.
        baseline = (hellos, tls_peers, queries, query_peers, rejected, connects, proxy_peers, proxy_rejected, plaintext, errors)
        def admission_guard(text: str, expected_error: str) -> None:
            profile.write_text(text, encoding="utf-8")
            with trace.lock:
                trace.event_locked("admission-guard-start", expectedError=expected_error)
            guarded = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=10, check=False)
            with trace.lock:
                trace.event_locked("admission-guard-exit", returnCode=guarded.returncode)
            if guarded.returncode == 0 or expected_error not in guarded.stderr:
                raise AssertionError(f"Unsafe fixture was not rejected by its pre-socket guard: {guarded.stdout} {guarded.stderr}")
            with trace.lock:
                after = (trace.hellos, trace.tls_peers, trace.queries, trace.query_peers, trace.rejected, trace.connects,
                         trace.proxy_peers, trace.proxy_rejected, trace.plaintext, trace.errors)
                if after != baseline:
                    raise AssertionError("Rejected fixture opened a socket or altered the wire trace")
        admission_guard(profile_text.replace(f"https://127.0.0.1:{first.server_address[1]}",
                                             f"https://127.0.0.2:{first.server_address[1]}", 1),
                        "endpoints must be distinct literal-loopback")
        if source_scope:
            # A source-pool profile may not silently expand its authority to
            # the monitored second peer. Reject before even first can dial.
            first_endpoint = f"encrypted-dns-server = https://127.0.0.1:{tls_ports[0]}/dns-query\n"
            extra_endpoint = first_endpoint[:-1] + f", https://127.0.0.1:{tls_ports[1]}/dns-query\n"
            admission_guard(profile_text.replace(first_endpoint, extra_endpoint, 1),
                            "Source-scope fixture requires exactly one explicit encrypted endpoint")
        if proxy:
            # Start from the valid profile, not the preceding malformed TLS
            # endpoint, so this proves the proxy guard independently.
            admission_guard(profile_text.replace(f"LoopbackHTTP = http, 127.0.0.1, {proxy.server_address[1]}",
                                                 f"LoopbackHTTP = http, 127.0.0.2, {proxy.server_address[1]}", 1),
                            "Production fixture proxy must be one literal-loopback HTTP port with no credentials or options")
        print(details)
        if base_scenario == "success":
            native = observed["functionalWitness"]
            empty_preconnect = [row for row in observed["proxyConnections"] if row.get("preConnectEmptyEOF") is True]
            print("DNS-ADAPTIVE-FUNCTIONAL-SERVER " + json.dumps({
                "scenario": scenario, "tlsReady": len(observed["tlsReady"]),
                "dnsQuestions": len(observed["queryDetails"]), "httpCONNECTs": len(observed["connects"]),
                "acceptedProxyPeers": len(observed["proxyPeers"]), "emptyPreCONNECTPeers": empty_preconnect,
                "registeredSoftHedgeLosers": sum(len(item["attempts"]) == 2 for item in native["registeredExchanges"]),
                "connectionPhaseCallbacks": native["connectionStage"]["count"],
                "connectionPhaseCancelledCallbacks": native["connectionStage"]["cancelled"],
                "proxyHandlersActive": observed["proxyHandlersActive"], "traditionalDNSQueries": observed["plaintext"],
                "evidenceBoundary": "registered CLI attempts + actual phase callbacks + closed server handlers; not per-socket kernel ACK"},
                sort_keys=True))
        if multi_upstream:
            print("DNS-MULTI-UPSTREAM-SERVER " + json.dumps({
                "scenario": scenario, "approvedEncryptedProviders": 2,
                "tlsStarted": len(observed["tlsPeers"]), "tlsReady": len(observed["tlsReady"]),
                "tlsClosed": len(observed["tlsClosed"]), "httpCONNECTs": len(observed["connects"]),
                "injectedFirstCONNECTFailures": len(observed["connectFailures"]),
                "dnsQuestions": len(observed["queryDetails"]), "dnsAnswersSent": len(observed["responseDetails"]),
                "providerQuestionCounts": dict(Counter(label for label, _, _, _ in observed["queryDetails"])),
                "traditionalDNSQueries": observed["plaintext"],
                "oldTLSCarriersClosedBeforeFreshEpoch": observed["scopeCheckpoints"][0]["tlsClosed"]}, sort_keys=True))
        if source_scope:
            carriers = {(label, tuple(peer)) for label, _, peer in observed["queryPeers"]}
            print("DNS-SOURCE-SCOPE-SERVER " + json.dumps({
                "approvedEncryptedProviders": 1,
                "unapprovedSecondTLSCarriers": sum(label == "second" for label in observed["tls"]),
                "tlsStarted": len(observed["tlsPeers"]), "tlsReady": len(observed["tlsReady"]),
                "tlsClosed": len(observed["tlsClosed"]), "tlsHandlersPeak": observed["tlsHandlersPeak"],
                "httpCONNECTs": len(observed["connects"]), "dnsQuestions": len(observed["queryDetails"]),
                "dnsAnswersSent": len(observed["responseDetails"]), "healthyPhysicalExchangePeak": observed["wirePeak"],
                "queryCarrierReuse": len(observed["queryDetails"]) - len(carriers),
                "traditionalDNSQueries": observed["plaintext"],
                "oldTLSCarriersClosedBeforeFreshEpoch": observed["scopeCheckpoints"][0]["tlsClosed"],
                "closeEvidence": "real TLS/CONNECT handlers drained before parent ACK, not logical cancel()"}, sort_keys=True))
        port_labels = {tls_ports[0]: "first", tls_ports[1]: "second"}
        proxy_summary = f", CONNECT={'/'.join(port_labels[port] for _, port in connects)}, proxy peers=127.0.0.1" if production else ""
        speculative_summary = f", approved DNS-empty speculative carriers={speculative}" if speculative else ""
        print(f"PASS adaptive {scenario}/flush: protection={str(protection).lower()}, "
              f"TLS={'/'.join(hellos)}, HTTPS-questions={len(queries)}{proxy_summary}{speculative_summary}, "
              "ordinary plaintext fallback=0, pre-socket guard")


def run_oracle_self_test() -> None:
    """Pure memory checks: no CA, socket, listener, app or user artifacts."""
    ports = {"first": 41001, "second": 41002}
    baseline = {
        "tls": ["first", "second", "first"],
        "tlsPeers": [("first", ("127.0.0.1", 42001)), ("second", ("127.0.0.1", 42002)),
                     ("first", ("127.0.0.1", 42003))],
        "queries": [("first", "adaptive.cold.example.test"), ("second", "adaptive.discover.example.test"),
                    ("second", "adaptive.preferred.example.test"), ("first", "adaptive.cold.example.test")],
        "queryPeers": [("first", "adaptive.cold.example.test", ("127.0.0.1", 42001)),
                       ("second", "adaptive.discover.example.test", ("127.0.0.1", 42002)),
                       ("second", "adaptive.preferred.example.test", ("127.0.0.1", 42002)),
                       ("first", "adaptive.cold.example.test", ("127.0.0.1", 42003))],
        "identityRejected": [], "connects": [("127.0.0.1", 41001), ("127.0.0.1", 41002), ("127.0.0.1", 41001)],
        "proxyPeers": ["127.0.0.1"] * 3, "proxyRejected": [], "plaintext": 0, "errors": []}
    successful = subprocess.CompletedProcess([], 0, "DNS adaptive loopback checks passed", "")
    positive = negative = 0

    def add_carrier(value: dict, label: str, port: int, position: int) -> None:
        value["tls"].insert(position, label)
        value["tlsPeers"].insert(position, (label, ("127.0.0.1", port)))
        value["connects"].insert(position, ("127.0.0.1", ports.get(label, 41999)))
        value["proxyPeers"].insert(position, "127.0.0.1")

    def check(value: dict, result=successful, base: str = "success") -> int:
        require_completed_cli(result)
        return validate_wire_trace(value, base, True, ports)

    def require_failure(name: str, value: dict, result=successful, base: str = "success") -> None:
        nonlocal negative
        try:
            check(value, result, base)
        except AssertionError:
            negative += 1
        else:
            raise AssertionError(f"Wire oracle wrongly accepted its negative self-check: {name}")

    for positions in ((), (1,), (3,), (1, 4)):
        value = deepcopy(baseline)
        for ordinal, position in enumerate(positions):
            add_carrier(value, "second", 42100 + ordinal, position)
        assert check(value) == len(positions)
        positive += 1
    value = deepcopy(baseline); value["connects"][0], value["connects"][1] = value["connects"][1], value["connects"][0]
    assert check(value) == 0; positive += 1
    for label, count in (("unknown", 1), ("first", 1), ("second", 3)):
        value = deepcopy(baseline)
        for ordinal in range(count): add_carrier(value, label, 42200 + ordinal, 1)
        require_failure(f"unapproved-or-excess-extra-{label}", value)
    for name in ("blocked.example.test", "adaptive.cold.example.test"):
        value = deepcopy(baseline)
        value["queries"].append(("second", name))
        value["queryPeers"].append(("second", name, ("127.0.0.1", 42002)))
        require_failure("QNAME-leak-or-duplicate", value)
    value = deepcopy(baseline); value["queryPeers"][2] = ("second", "adaptive.preferred.example.test", ("127.0.0.1", 42004))
    require_failure("preferred-reconnected", value)
    value = deepcopy(baseline); value["queryPeers"][3] = ("first", "adaptive.cold.example.test", ("127.0.0.1", 42001))
    require_failure("flush-reused-stale-peer", value)
    value = deepcopy(baseline); value["tlsPeers"][1] = ("second", ("127.0.0.2", 42002))
    require_failure("off-loopback-TLS", value)
    value = deepcopy(baseline); value["connects"][1] = ("127.0.0.1", 41999)
    require_failure("CONNECT-unapproved-port", value)
    value = deepcopy(baseline); value["connects"].pop()
    require_failure("CONNECT-count-mismatch", value)
    for key, bad in (("proxyPeers", ["127.0.0.2"] * 3), ("plaintext", 1),
                     ("errors", ["TLS validation failed"]), ("proxyRejected", ["Unexpected target"])):
        value = deepcopy(baseline); value[key] = bad
        require_failure(key, value)
    # The unchanged Core validates RCODE/answer/ownership. Even if it emitted a
    # success marker before another failure, no wire allowance may hide exit 1.
    for message in ("RCODE mismatch", "Core failed"):
        require_failure(message, deepcopy(baseline), subprocess.CompletedProcess([], 1, successful.stdout, message))
    identity = deepcopy(baseline)
    identity.update({"tls": ["first", "second", "first", "second"], "identityRejected": ["first", "first"],
                     "tlsPeers": [("first", ("127.0.0.1", 42001)), ("second", ("127.0.0.1", 42002)),
                                  ("first", ("127.0.0.1", 42003)), ("second", ("127.0.0.1", 42004))],
                     "queries": [("second", "adaptive.identity.example.test"),
                                 ("second", "adaptive.identity-next.example.test"),
                                 ("second", "adaptive.identity.example.test")],
                     "queryPeers": [("second", "adaptive.identity.example.test", ("127.0.0.1", 42002)),
                                    ("second", "adaptive.identity-next.example.test", ("127.0.0.1", 42002)),
                                    ("second", "adaptive.identity.example.test", ("127.0.0.1", 42004))],
                     "connects": [("127.0.0.1", 41001), ("127.0.0.1", 41002)] * 2,
                     "proxyPeers": ["127.0.0.1"] * 4})
    assert check(identity, base="identity-failure") == 0; positive += 1
    value = deepcopy(identity); value["identityRejected"] = []
    require_failure("SAN-rejection-disappeared", value, base="identity-failure")
    value = deepcopy(identity); value["queries"].append(("first", "adaptive.identity.example.test"))
    require_failure("wrong-SAN-provider-received-question", value, base="identity-failure")
    value = deepcopy(identity); add_carrier(value, "second", 42300, 1)
    require_failure("identity-extra-not-permitted", value, base="identity-failure")
    print(f"Adaptive wire-oracle self-check passed: {positive} positive, {negative} negative; memory only, no sockets/app/build")
    run_source_scope_oracle_self_test()
    run_source_scope_timing_capture_self_test()
    run_multi_upstream_oracle_self_test()
    run_functional_witness_oracle_self_test()
    run_identity_evidence_oracle_self_test()


def run_identity_evidence_oracle_self_test() -> None:
    """Joint SDK/loaded-certificate/native-result/forward proofs; memory only."""
    ports = {"first": 41001, "second": 41002}; proxy = ("127.0.0.1", 41003)
    peers = [("first" if index % 2 == 0 else "second", ("127.0.0.1", 42001 + index)) for index in range(4)]
    # Synthetic memory-only artifacts, not substitutes for the actual
    # SSLContext PEM/child CA DER fingerprints required by a live fixture.
    leaf_sha256 = {"first": "11" * 32, "second": "22" * 32}; anchor_sha256 = "aa" * 32
    certificate = {"actualNWErrorTLS": True, "swiftType": "Network.NWError", "NWErrorKind": "tls",
                   "NWErrorCode": -9843, "classification": "authentication", "NSErrorDomain": "typed TLS", "NSErrorCode": -9843}
    proof = {"formatVersion": 1, "fixtureOnly": True, "scenario": IDENTITY_SCENARIO,
             "successAssertionsCompleted": True, "binding": "passive existing TLS ClientHello.random",
             "recordLimit": 128, "prefixBytesLimit": 43, "rawReady": 4, "tlsReady": 2, "tlsFailures": 2,
             "pendingCallbacks": 0, "droppedRecords": 0, "invalidObservations": 0, "nativeWriteFailures": 0,
             "approvedProviderPorts": [41001, 41002], "approvedProxy": {"name": "LoopbackHTTP", "host": "127.0.0.1", "port": 41003},
             "answers": [[0x7301, 0, "203.0.113.81"], [0x7302, 0, "203.0.113.81"], [0x7303, 5, None], [0x7304, 0, "203.0.113.81"]],
             "records": []}
    observed = {"identityObservation": True, "identityWitness": proof, "identityRejected": [],
                "providers": [{"provider": label, "authority": f"127.0.0.1:{ports[label]}", "identityFailure": label == "first",
                               "loadedLeafSHA256": leaf_sha256[label], "fixtureAnchorSHA256": anchor_sha256}
                              for label in ("first", "second")],
                "tls": [label for label, _ in peers], "tlsPeers": peers, "tlsReady": [peers[1], peers[3]], "tlsClosed": peers,
                "approvedProxyEndpoint": proxy, "proxyConnections": [], "proxyRejected": [], "plaintext": 0,
                "tlsHandlersActive": 0, "proxyHandlersActive": 0, "wireActive": 0,
                "connects": [("127.0.0.1", ports[label]) for label, _ in peers], "proxyPeers": ["127.0.0.1"] * 4,
                "queries": [("second", name) for name in ("adaptive.identity.example.test", "adaptive.identity-next.example.test", "adaptive.identity.example.test")],
                "queryDetails": [("second", name, identifier, peers[1 if index < 2 else 3][1]) for index, (name, identifier) in enumerate(
                    [("adaptive.identity.example.test", 0x7301), ("adaptive.identity-next.example.test", 0x7302), ("adaptive.identity.example.test", 0x7304)])],
                "identitySSLErrors": [], "errors": ["opaque SSL close A", "opaque SSL close B"]}
    for index, (label, peer) in enumerate(peers):
        prefix = b"\x16\x03\x01\x00\x40\x01\x00\x00\x3c\x03\x03" + bytes([index + 1]) * 32
        failed = label == "first"
        token = f"00000000-0000-4000-8000-{index + 1:012d}"
        trust = {"ownerToken": token, "startCount": 1, "returnCount": 1, "callbackCount": 1,
                 "startedAt": 1.2, "returnedAt": 1.3, "callbackAt": 1.5, "returnStatus": 0,
                 "trusted": not failed, "hasError": failed, "errorIsCFError": failed,
                 "errorDomain": IDENTITY_ERROR_DOMAIN if failed else None,
                 "errorCode": IDENTITY_HOSTNAME_MISMATCH if failed else None,
                 "certificateCount": 2, "leafSHA256": leaf_sha256[label],
                 "evaluatedAnchorSHA256": anchor_sha256, "fixtureAnchorSHA256": anchor_sha256}
        proof["records"].append({"token": token, "ordinal": index, "provider": index % 2,
            "port": ports[label], "clientHelloPrefixHex": prefix.hex(), "clientHelloPrefixBytes": 43,
            "prefixWrites": 1, "prefixCallbacks": 1, "prefixWrittenBytes": 43, "prefixWriteFailures": 0, "prefixWriteError": None,
            "rawReadyAt": 0, "nativeTLSStartedAt": 1, "firstPrefixCallbackAt": 1.1, "lastPrefixCallbackAt": 1.1,
            "rawCancelAt": 3 if failed else None, "rawCancelCount": 1 if failed else 0,
            "ownCancelAt": 5 if failed else None, "rawTerminalAt": 3.1 if failed else None, "rawTerminalError": None,
            "certificateObserverAt": 2 if failed else None, "certificateError": deepcopy(certificate) if failed else None,
            "firstObserverAt": 2 if failed else None, "firstObserverError": deepcopy(certificate) if failed else None,
            "lastObserverAt": 3.5 if failed else None, "lastObserverError": deepcopy(certificate) if failed else None,
            "firstUnknownObserverAt": None, "observerCount": 2 if failed else 0,
            "nativeResultAt": 4, "nativeResult": "failure" if failed else "success", "nativeResultCount": 1,
            "nativeError": deepcopy(certificate) if failed else None, "handoffAt": 4.1,
            "httpSends": 0 if failed else (2 if index == 1 else 1), "applicationBytes": 0 if failed else 200,
            "trustEvaluation": trust})
        observed["proxyConnections"].append({"identityCapture": True, "connectHeaderComplete": True, "upstreamOpened": True,
            "closedSeconds": 3, "proxyEndpoint": proxy, "peer": ("127.0.0.1", 43001 + index),
            "tlsPeer": peer, "targetPort": ports[label], "identityProvider": label,
            "helloForwardedBytes": 43, "helloPrefixHex": prefix.hex()})
        if failed:
            observed["identitySSLErrors"].append({"provider": label, "peer": peer, "phase": "tls-handshake", "actualSSLError": True,
                "errorType": "ssl.SSLEOFError", "authenticated": False, "errorIndex": index // 2})
    positive = negative = 0

    def check(value):
        return validate_wire_trace(value, "identity-failure", True, ports)

    def reject(name, mutate):
        nonlocal negative
        value = deepcopy(observed); mutate(value)
        try:
            check(value)
        except AssertionError:
            negative += 1
        else:
            raise AssertionError(f"Identity proof wrongly accepted its negative self-check: {name}")

    assert check(observed) == 0; positive += 1
    for code in (-9807, -9843):
        value = deepcopy(observed)
        for index in (0, 2):
            for field in ("certificateError", "nativeError", "firstObserverError", "lastObserverError"):
                value["identityWitness"]["records"][index][field].update(
                    {"NWErrorCode": code, "NSErrorDomain": IDENTITY_ERROR_DOMAIN, "NSErrorCode": code})
        assert check(value) == 0; positive += 1
    value = deepcopy(observed)
    for record in value["identityWitness"]["records"]:
        record.update({"prefixWrites": 43, "prefixCallbacks": 43})
    assert check(value) == 0; positive += 1
    value = deepcopy(observed)
    value["identitySSLErrors"][0]["errorType"] = "ssl.SSLError"; value["identityRejected"] = ["first"]
    assert check(value) == 0; positive += 1
    value = deepcopy(observed)
    value["identityWitness"]["records"][0]["firstUnknownObserverAt"] = 3.1
    assert check(value) == 0; positive += 1  # Cleanup remains evidence, never the certificate proof.

    def generic_native_certificates(value):
        for index in (0, 2):
            for field in ("certificateError", "nativeError", "firstObserverError", "lastObserverError"):
                value["identityWitness"]["records"][index][field].update(
                    {"NWErrorCode": -9808, "NSErrorDomain": IDENTITY_ERROR_DOMAIN, "NSErrorCode": -9808})

    # Two new positives: the actual hostname CFError jointly proves a generic
    # native certificate error, and the SDK is allowed to complete inline.
    value = deepcopy(observed); generic_native_certificates(value)
    assert check(value) == 0; positive += 1
    value = deepcopy(observed)
    for record in value["identityWitness"]["records"]:
        record["trustEvaluation"]["returnedAt"] = 1.6  # Original callback at 1.5, before return.
    assert check(value) == 0; positive += 1

    # Original first authentication survives a real later unknown cleanup;
    # the cleanup metadata is retained, never substituted for that first deny.
    value = deepcopy(observed)
    value["identityWitness"]["records"][0].update({"observerCount": 3, "firstUnknownObserverAt": 3.5,
        "lastObserverAt": 3.5, "lastObserverError": {"swiftType": "Foundation.NSError", "actualNWErrorTLS": False,
            "NSErrorDomain": "app.hajimi.cpp-protocol", "NSErrorCode": 1, "classification": "other"}})
    assert check(value) == 0; positive += 1

    reject("missing-first-native-error", lambda value: value["identityWitness"]["records"][0].pop("firstObserverError"))
    reject("null-first-native-error", lambda value: value["identityWitness"]["records"][0].__setitem__("firstObserverError", None))
    for field, wrong in (("actualNWErrorTLS", False), ("swiftType", "NSError"), ("NWErrorKind", "posix"),
                         ("classification", "other"), ("classification", "configuration"), ("classification", "capacity"),
                         ("NWErrorCode", -9807)):
        reject(f"first-native-error-{field}-{wrong!r}", lambda value, field=field, wrong=wrong:
               value["identityWitness"]["records"][0]["firstObserverError"].__setitem__(field, wrong))
    reject("missing-first-native-error-time", lambda value: value["identityWitness"]["records"][0].pop("firstObserverAt"))
    for wrong in (None, 1.9, 2.1, True):
        reject(f"first-native-error-time-{wrong!r}", lambda value, wrong=wrong:
               value["identityWitness"]["records"][0].__setitem__("firstObserverAt", wrong))

    reject("missing-SDK-evidence", lambda value: value["identityWitness"]["records"][0].pop("trustEvaluation"))
    reject("null-SDK-evidence", lambda value: value["identityWitness"]["records"][0].__setitem__("trustEvaluation", None))
    for name, changes in (("generic--9808-alone", None),
                          ("generic--9808-without-CFError", {"hasError": False, "errorIsCFError": False, "errorDomain": None, "errorCode": None}),
                          ("generic--9808-non-hostname-CFError", {"errorCode": -9808})):
        def corrupt_generic(value, changes=changes):
            generic_native_certificates(value)
            record = value["identityWitness"]["records"][0]
            if changes is None:
                record.pop("trustEvaluation")
            else:
                record["trustEvaluation"].update(changes)
        reject(name, corrupt_generic)
    for field in IDENTITY_TRUST_KEYS:
        reject(f"missing-SDK-{field}", lambda value, field=field: value["identityWitness"]["records"][0]["trustEvaluation"].pop(field))
    for field in ("startCount", "returnCount", "callbackCount"):
        for wrong in (0, 2, True):
            reject(f"SDK-{field}-{wrong!r}", lambda value, field=field, wrong=wrong:
                   value["identityWitness"]["records"][0]["trustEvaluation"].__setitem__(field, wrong))
    for field, wrong in (("ownerToken", proof["records"][1]["token"]), ("returnStatus", -50), ("returnStatus", True),
                         ("startedAt", 1.6), ("startedAt", -1), ("returnedAt", 1.1), ("returnedAt", float("nan")),
                         ("callbackAt", 1.1), ("callbackAt", 2.1), ("callbackAt", 3.01), ("callbackAt", 4.01), ("callbackAt", float("inf")),
                         ("trusted", True), ("trusted", 1), ("trusted", None), ("hasError", False), ("hasError", 1),
                         ("errorIsCFError", False), ("errorIsCFError", 1), ("errorDomain", None),
                         ("errorDomain", "kCFErrorDomainTLS"), ("errorDomain", "x" * 257),
                         ("errorCode", None), ("errorCode", -67608), ("errorCode", -9808), ("errorCode", "-67602"), ("errorCode", True),
                         ("certificateCount", 0), ("certificateCount", 1), ("certificateCount", 17), ("certificateCount", True),
                         ("leafSHA256", leaf_sha256["second"]), ("leafSHA256", "ff" * 32), ("leafSHA256", "FF" * 32), ("leafSHA256", None),
                         ("evaluatedAnchorSHA256", "ff" * 32), ("evaluatedAnchorSHA256", leaf_sha256["second"]), ("evaluatedAnchorSHA256", None),
                         ("fixtureAnchorSHA256", "ff" * 32), ("fixtureAnchorSHA256", leaf_sha256["second"]), ("fixtureAnchorSHA256", None)):
        reject(f"SDK-{field}-{wrong!r}", lambda value, field=field, wrong=wrong:
               value["identityWitness"]["records"][0]["trustEvaluation"].__setitem__(field, wrong))
    for field, wrong in (("trusted", False), ("hasError", True), ("errorIsCFError", True), ("errorDomain", IDENTITY_ERROR_DOMAIN),
                         ("errorCode", IDENTITY_HOSTNAME_MISMATCH), ("leafSHA256", leaf_sha256["first"]),
                         ("evaluatedAnchorSHA256", "ff" * 32), ("fixtureAnchorSHA256", "ff" * 32), ("callbackAt", 4.01)):
        reject(f"healthy-SDK-{field}", lambda value, field=field, wrong=wrong:
               value["identityWitness"]["records"][1]["trustEvaluation"].__setitem__(field, wrong))
    for field in ("loadedLeafSHA256", "fixtureAnchorSHA256"):
        reject(f"missing-independent-{field}", lambda value, field=field: value["providers"][0].pop(field))
    for field, wrong in (("loadedLeafSHA256", "ff" * 32), ("fixtureAnchorSHA256", "ff" * 32),
                         ("loadedLeafSHA256", leaf_sha256["second"]), ("loadedLeafSHA256", anchor_sha256),
                         ("loadedLeafSHA256", True), ("fixtureAnchorSHA256", leaf_sha256["first"])):
        reject(f"independent-{field}-{wrong!r}", lambda value, field=field, wrong=wrong: value["providers"][0].__setitem__(field, wrong))
    for key, wrong in (("formatVersion", True), ("successAssertionsCompleted", False), ("rawReady", 3), ("recordLimit", 129),
                       ("prefixBytesLimit", 44), ("pendingCallbacks", 1), ("droppedRecords", 1), ("invalidObservations", 1), ("nativeWriteFailures", 1)):
        reject(key, lambda value, key=key, wrong=wrong: value["identityWitness"].__setitem__(key, wrong))
    for field, wrong in (("prefixCallbacks", 0), ("prefixWriteFailures", 1), ("prefixWrittenBytes", 42), ("rawCancelCount", 0),
                         ("nativeResultCount", 2), ("nativeResult", "success"), ("httpSends", 1), ("applicationBytes", 1),
                         ("certificateObserverAt", 3), ("ownCancelAt", 1.9), ("rawTerminalAt", 1.9),
                         ("firstUnknownObserverAt", 1.9), ("firstUnknownObserverAt", 2.5)):
        reject(field, lambda value, field=field, wrong=wrong: value["identityWitness"]["records"][0].__setitem__(field, wrong))
    for field, wrong in (("actualNWErrorTLS", False), ("swiftType", "NSError"), ("NWErrorKind", "posix"), ("NWErrorCode", -9802),
                         ("classification", "other"), ("NativeOutboundErrorCase", "cancelled")):
        for target in ("certificateError", "nativeError"):
            reject(f"{target}-{field}", lambda value, field=field, wrong=wrong, target=target:
                   value["identityWitness"]["records"][0][target].__setitem__(field, wrong))
    reject("missing-record", lambda value: value["identityWitness"]["records"].pop())
    for key in ("ownCancelAt", "firstUnknownObserverAt", "rawTerminalAt"):
        reject(f"missing-{key}", lambda value, key=key: value["identityWitness"]["records"][0].pop(key))
    reject("oversized-proof", lambda value: value["identityWitness"].__setitem__("padding", "x" * 16_384))
    reject("duplicate-random", lambda value: value["identityWitness"]["records"][1].__setitem__(
           "clientHelloPrefixHex", value["identityWitness"]["records"][0]["clientHelloPrefixHex"]))
    reject("node-mismatch", lambda value: value["identityWitness"]["approvedProxy"].__setitem__("port", 41999))
    for field, wrong in (("identityCapture", False), ("helloForwardedBytes", 42), ("targetPort", 41002),
                         ("identityProvider", "second"), ("tlsPeer", ("127.0.0.1", 42999)), ("closedSeconds", None)):
        reject(f"relay-{field}", lambda value, field=field, wrong=wrong: value["proxyConnections"][0].__setitem__(field, wrong))
    for field, wrong in (("actualSSLError", False), ("errorType", "OSError"), ("phase", "application"), ("provider", "second"),
                         ("peer", ("127.0.0.1", 42999)), ("errorIndex", 1), ("authenticated", True)):
        reject(f"SSL-{field}", lambda value, field=field, wrong=wrong: value["identitySSLErrors"][0].__setitem__(field, wrong))
    reject("extra-unknown-error", lambda value: value["errors"].append("unknown"))
    reject("missing-SSL-proof", lambda value: value["identitySSLErrors"].pop())
    reject("accepted-wrong-SAN", lambda value: value["tlsReady"].append(peers[0]))
    reject("first-DNS-payload", lambda value: value["queryDetails"].append(("first", "adaptive.identity.example.test", 0x7301, peers[0][1])))
    prefix = bytes.fromhex(proof["records"][0]["clientHelloPrefixHex"])
    for name, malformed in (("short", prefix[:-1]), ("application-record", bytes([23]) + prefix[1:]),
                            ("wrong-version", prefix[:1] + bytes([4]) + prefix[2:]),
                            ("cross-record", prefix[:3] + b"\x00\x26" + prefix[5:])):
        try:
            client_hello_random(malformed)
        except AssertionError:
            negative += 1
        else:
            raise AssertionError(f"Identity prefix parser accepted {name}")
    trace, observation, captured = Trace(), {}, bytearray()
    capture_forwarded_client_hello(captured, prefix[:2], 2, trace, observation)
    capture_forwarded_client_hello(captured, prefix[2:] + b"not captured", len(prefix) - 2 + 12, trace, observation)
    assert bytes(captured) == prefix and observation["helloForwardedBytes"] == 43; positive += 1
    for written in (0, -1, 44, True):
        try:
            capture_forwarded_client_hello(bytearray(), prefix, written, trace, {})
        except AssertionError:
            negative += 1
        else:
            raise AssertionError("Identity collector accepted a non-positive/non-real socket write receipt")
    print(f"Identity SecTrust/loaded-certificate/native/random/peer oracle self-check passed: {positive} positive, {negative} negative; memory only")


def run_source_scope_oracle_self_test() -> None:
    """Adversarial source-scope counter/wire witnesses, wholly in memory."""
    ports = {"first": 41001, "second": 41002}
    preflight = ("first", ("127.0.0.1", 42400))
    old = ("first", ("127.0.0.1", 42401))
    fresh = ("first", ("127.0.0.1", 42402))
    questions = [("first", "scope.shared.example.test", 0x7400 + index * 2, old[1]) for index in range(96)]
    questions += [("first", f"scope.burst-{index}.example.test", 0x7600 + index, old[1]) for index in range(256)]
    questions += [("first", "scope.shared.example.test", 0x7701, fresh[1])]
    fence = {"version": 1, "phase": "flush-closed", "tlsStarted": 2, "tlsReady": 2, "tlsClosed": 2,
             "tlsHandlersActive": 0, "connectHandlersActive": 0, "traditionalQueries": 0,
             "clientHTTPQueries": 352, "serverQuestions": 352, "serverAnswers": 352,
             "closedPeers": [preflight, old]}
    baseline = {"tls": ["first"] * 3, "tlsPeers": [preflight, old, fresh],
                "tlsReady": [preflight, old, fresh], "tlsClosed": [preflight, old, fresh],
                "preflightACKs": [(preflight[0], preflight[1], SOURCE_SCOPE_PREFLIGHT_ACK.hex())],
                "queries": [(label, name) for label, name, _, _ in questions],
                "queryPeers": [(label, name, peer) for label, name, _, peer in questions],
                "queryDetails": questions, "responseDetails": list(questions),
                "connects": [("127.0.0.1", ports["first"])] * 3, "proxyPeers": ["127.0.0.1"] * 3,
                "identityRejected": [], "proxyRejected": [], "errors": [], "plaintext": 0,
                "tlsHandlersActive": 0, "tlsHandlersPeak": 2, "wireActive": 0, "wirePeak": 1,
                "scopeCheckpoints": [fence]}
    logical = {"queries": 449, "completedClients": 450, "upstreamLeaders": 352, "mergedClients": 96,
               "cacheHits": 1, "logicalActivePeak": 16, "logicalQueuedPeak": 240,
               "logicalWaitingClientsPeak": 256, "activeLimit": 16, "leaderCapacity": 512,
               "failures": 0, "capacityFailures": 0, "timeoutFailures": 0,
               "maximumSuccessfulMilliseconds": 450.0, "perQueryDeadlineMilliseconds": 8000}
    physical = {"approvedEncryptedProviders": 1, "preflightRawReady": 1, "preflightTLSReady": 1, "preflightDNSQueries": 0,
                "preflightAcknowledgementBytes": len(SOURCE_SCOPE_PREFLIGHT_ACK), "preflightAuthenticatedACK": True,
                "dnsRawCarrierReady": 1, "dnsTLSReady": 1, "tlsFailures": 0,
                "clientHTTPQueries": 352, "encryptedConnectionReuse": 351}
    flushed = {"oldTLSCarriersClosedByServer": 2, "newEpochRawCarriers": 1, "newEpochWireQueries": 1,
               "serverCloseFence": True, "logicalActive": 0, "logicalPending": 0}

    def output(one=logical, two=physical, three=flushed) -> str:
        return "\n".join(marker + " " + json.dumps(value) for marker, value in (
            ("DNS-SOURCE-SCOPE-LOGICAL", one), ("DNS-SOURCE-SCOPE-PHYSICAL", two), ("DNS-SOURCE-SCOPE-FLUSH", three)))

    def consistent_ledger(value: dict) -> None:
        rows = value["queryDetails"]
        value["queries"] = [(label, name) for label, name, _, _ in rows]
        value["queryPeers"] = [(label, name, peer) for label, name, _, peer in rows]
        value["responseDetails"] = list(rows)

    positive = negative = 0
    validate_source_scope_wire_trace(baseline, True, ports)
    validate_source_scope_cli_output(output()); positive += 1
    value = deepcopy(baseline)
    for index in range(96):
        label, name, identifier, peer = value["queryDetails"][index]
        value["queryDetails"][index] = (label, name, identifier + 1, peer)
    consistent_ledger(value)
    validate_source_scope_wire_trace(value, True, ports); positive += 1

    def bad_wire(name: str, mutate) -> None:
        nonlocal negative
        value = deepcopy(baseline); mutate(value)
        try:
            validate_source_scope_wire_trace(value, True, ports)
        except AssertionError:
            negative += 1
        else:
            raise AssertionError(f"Source-scope oracle accepted its negative: {name}")

    def replace_query(value: dict, index: int, row: tuple) -> None:
        value["queryDetails"][index] = row; consistent_ledger(value)

    bad_wire("cross-source-merge", lambda value: replace_query(value, 1, value["queryDetails"][0]))
    bad_wire("cached-query-reached-network", lambda value: replace_query(value, 0,
        ("first", "scope.shared.example.test", 0x7500, old[1])))
    bad_wire("QNAME-REJECT-reached-network", lambda value: replace_query(value, 0,
        ("first", "blocked.example.test", 0x7400, old[1])))
    bad_wire("unique-query-ID-changed", lambda value: replace_query(value, 100,
        ("first", "scope.burst-4.example.test", 0x7605, old[1])))
    bad_wire("flush-used-old-carrier", lambda value: replace_query(value, 352,
        ("first", "scope.shared.example.test", 0x7701, old[1])))
    for key, bad in (("wirePeak", 17), ("plaintext", 1), ("tlsHandlersActive", 1), ("wireActive", 1),
                     ("errors", ["TLS failed"]), ("identityRejected", ["first"]), ("proxyRejected", ["bad target"]),
                     ("tlsReady", [preflight, old]), ("tlsClosed", [preflight, old]), ("scopeCheckpoints", [])):
        bad_wire(key, lambda value, key=key, bad=bad: value.update({key: bad}))
    bad_wire("server-answer-missing", lambda value: value["responseDetails"].pop())
    bad_wire("unapproved-CONNECT", lambda value: value["connects"].__setitem__(0, ("127.0.0.1", 41999)))
    bad_wire("monitored-secondary-CONNECT", lambda value: value["connects"].__setitem__(0, ("127.0.0.1", ports["second"])))
    bad_wire("physical-close-fence-incomplete", lambda value: value["scopeCheckpoints"][0].update({"tlsClosed": 1}))
    bad_wire("empty-speculative-secondary", lambda value: value["tls"].__setitem__(1, "second"))
    bad_wire("preflight-ACK-missing", lambda value: value.update({"preflightACKs": []}))
    bad_wire("preflight-ACK-duplicated", lambda value: value["preflightACKs"].append(value["preflightACKs"][0]))
    bad_wire("preflight-ACK-queried-carrier", lambda value: value.update({
        "preflightACKs": [(old[0], old[1], SOURCE_SCOPE_PREFLIGHT_ACK.hex())]}))
    bad_wire("preflight-ACK-unobserved-peer", lambda value: value.update({
        "preflightACKs": [("first", ("127.0.0.1", 42999), SOURCE_SCOPE_PREFLIGHT_ACK.hex())]}))
    bad_wire("preflight-ACK-truncated", lambda value: value.update({
        "preflightACKs": [(preflight[0], preflight[1], SOURCE_SCOPE_PREFLIGHT_ACK[:-1].hex())]}))
    bad_wire("preflight-ACK-trailing-bytes", lambda value: value.update({
        "preflightACKs": [(preflight[0], preflight[1], (SOURCE_SCOPE_PREFLIGHT_ACK + b"x").hex())]}))

    for category, key, bad in (("logical", "logicalActivePeak", 32), ("logical", "logicalQueuedPeak", 513),
                              ("logical", "capacityFailures", 1), ("logical", "mergedClients", 95),
                              ("logical", "perQueryDeadlineMilliseconds", 12000),
                              ("logical", "maximumSuccessfulMilliseconds", 8001),
                              ("physical", "approvedEncryptedProviders", 2),
                              ("physical", "dnsRawCarrierReady", 256), ("physical", "preflightDNSQueries", 1),
                              ("physical", "preflightAcknowledgementBytes", len(SOURCE_SCOPE_PREFLIGHT_ACK) - 1),
                              ("physical", "preflightAuthenticatedACK", False),
                              ("physical", "preflightAuthenticatedACK", 1),
                              ("physical", "encryptedConnectionReuse", 0), ("flush", "serverCloseFence", False),
                              ("flush", "newEpochRawCarriers", 0), ("flush", "oldTLSCarriersClosedByServer", 1)):
        one, two, three = deepcopy(logical), deepcopy(physical), deepcopy(flushed)
        {"logical": one, "physical": two, "flush": three}[category][key] = bad
        try:
            validate_source_scope_cli_output(output(one, two, three))
        except AssertionError:
            negative += 1
        else:
            raise AssertionError(f"Source-scope counter oracle accepted its negative: {category}/{key}")
    print(f"Source-scope wire/counter oracle self-check passed: {positive} positive, {negative} negative; memory only")


def run_source_scope_timing_capture_self_test() -> None:
    value = {"formatVersion": 1, "fixtureOnly": True, "successAssertionsCompleted": False,
             "physical": {"rawReady": 32, "pendingTLSCallbacks": 16}}
    marker = SOURCE_SCOPE_TIMING_MARKER + json.dumps(value)
    trace = Trace()
    capture_source_scope_timing("earlier CLI assertion failed\n" + marker, trace)
    if trace.snapshot()["sourceScopeTiming"] != value:
        raise AssertionError("Source-scope timing was lost behind an earlier CLI failure")
    cases = (("missing", "unrelated failure without the diagnostic"), ("duplicate", marker + "\n" + marker),
             ("invalid-json", SOURCE_SCOPE_TIMING_MARKER + "{"),
             ("invalid-format", SOURCE_SCOPE_TIMING_MARKER + "[]"),
             ("invalid-format", SOURCE_SCOPE_TIMING_MARKER + '{"formatVersion":true,"fixtureOnly":true}'),
             ("too-large", SOURCE_SCOPE_TIMING_MARKER + json.dumps({**value, "padding": "x" * 16_384})))
    for reason, details in cases:
        capture_source_scope_timing(details, trace)
        if trace.snapshot()["sourceScopeTiming"] != {"available": False, "observationError": reason}:
            raise AssertionError(f"Bounded timing capture did not reject its {reason} diagnostic")
    print("Source-scope failure timing capture self-check passed: 7 memory-only checks")


def run_multi_upstream_oracle_self_test() -> None:
    """Both approved addresses pass, while cross-provider/source forgeries fail."""
    ports = {"first": 41001, "second": 41002}
    preflight = ("first", ("127.0.0.1", 42500))
    first = ("first", ("127.0.0.1", 42501))
    second = ("second", ("127.0.0.1", 42502))
    new_first = ("first", ("127.0.0.1", 42503))
    new_second = ("second", ("127.0.0.1", 42504))
    peers = [preflight, first, second, new_first, new_second]
    questions = [(carrier[0], "scope.shared.example.test", 0x7400 + index * 2, carrier[1])
                 for index in range(96) for carrier in [first if index % 2 == 0 else second]]
    questions += [(carrier[0], f"scope.burst-{index}.example.test", 0x7600 + index, carrier[1])
                  for index in range(256) for carrier in [first if index % 2 == 0 else second]]
    questions += [(new_second[0], "scope.shared.example.test", 0x7701, new_second[1])]
    fence = {"version": 1, "phase": "flush-closed", "tlsStarted": 3, "tlsReady": 3, "tlsClosed": 3,
             "tlsHandlersActive": 0, "connectHandlersActive": 0, "traditionalQueries": 0,
             "clientHTTPQueries": 352, "serverQuestions": 352, "serverAnswers": 352,
             "connectAttempts": 3, "connectFailures": 0, "closedPeers": peers[:3]}
    baseline = {"tls": [label for label, _ in peers], "tlsPeers": peers,
                "tlsReady": list(peers), "tlsClosed": list(peers),
                "preflightACKs": [(preflight[0], preflight[1], SOURCE_SCOPE_PREFLIGHT_ACK.hex())],
                "queryDetails": questions, "responseDetails": list(questions),
                "connects": [("127.0.0.1", ports[label]) for label, _ in peers], "connectFailures": [],
                "proxyPeers": ["127.0.0.1"] * len(peers), "identityRejected": [], "proxyRejected": [],
                "errors": [], "plaintext": 0, "tlsHandlersActive": 0, "wireActive": 0, "wirePeak": 2,
                "scopeCheckpoints": [fence]}

    def ledger(value: dict, *, answers: bool = False) -> None:
        rows = value["queryDetails"]
        value["queries"] = [(label, name) for label, name, _, _ in rows]
        value["queryPeers"] = [(label, name, peer) for label, name, _, peer in rows]
        value["responseDetails"] = list(rows)
        if answers:
            reply_addresses = {}
            for label, name, identifier, _ in rows:
                address = "203.0.113.80" if label == "first" else "203.0.113.81"
                if name == "scope.shared.example.test" and 0x7400 <= identifier < 0x74C0:
                    leader = 0x7400 + ((identifier - 0x7400) // 2) * 2
                    reply_addresses[leader] = reply_addresses[leader + 1] = address
                else:
                    reply_addresses[identifier] = address
            reply_addresses[0x7500] = reply_addresses[0x7400]
            value["multiUpstreamClientAnswers"] = [[key, reply_addresses[key]] for key in sorted(reply_addresses)]

    ledger(baseline, answers=True)
    positive = negative = 0

    def evidence(value: dict) -> None:
        carriers = [(label, tuple(peer)) for label, peer in value["tlsPeers"]]
        bindings = []; records = []
        for ordinal, (label, peer) in enumerate(carriers):
            nonce = f"00000000-0000-0000-0000-{ordinal + 1:012X}"
            bindings.append({"nonce": nonce, "ordinal": ordinal, "provider": label, "peer": peer, "extraProtocol": True})
            count = sum((provider, tuple(qpeer)) == (label, peer) for provider, _, _, qpeer in value["queryDetails"])
            records.append([nonce, ordinal, 0 if label == "first" else 1, 1.0, 2.0, None, 3.0, 4.0,
                            "success", None, None, None, None, count, None, 0, False, False])
        value.update({"carrierBindings": bindings, "handshakeEOFs": [], "carrierProof": {
            "formatVersion": 1, "fixtureOnly": True, "recordLimit": 128, "columns": list(CARRIER_PROOF_COLUMNS),
            "rawReady": len(records), "tlsReady": len(records), "typedTLSCancelled": 0,
            "tlsFailures": 0, "preludeFailures": 0, "records": records}})

    evidence(baseline)
    def check(value: dict, scenario: str = "multi-upstream-burst") -> None:
        validate_multi_upstream_wire_trace(value, True, ports, scenario)

    check(baseline); positive += 1
    only_second = deepcopy(baseline)
    only_second["queryDetails"] = [("second", name, identifier, new_second[1] if identifier == 0x7701 else second[1])
                                   for _, name, identifier, _ in questions]
    ledger(only_second, answers=True); evidence(only_second); check(only_second); positive += 1
    # Coalescing may elect the second client ID, but must restore both IDs.
    odd_leaders = deepcopy(baseline)
    for index in range(96):
        label, name, identifier, peer = odd_leaders["queryDetails"][index]
        odd_leaders["queryDetails"][index] = (label, name, identifier + 1, peer)
    ledger(odd_leaders, answers=True); check(odd_leaders); positive += 1

    # Both approved providers may send an authenticated reply for the SAME
    # original ID; actual client selection, not last server event, is winner.
    dual = deepcopy(baseline)
    dual["queryDetails"].append(("second", "scope.shared.example.test", 0x7400, second[1]))
    ledger(dual); evidence(dual)
    dual["scopeCheckpoints"][0].update({"clientHTTPQueries": 353, "serverQuestions": 353, "serverAnswers": 353})
    check(dual); positive += 1
    dual_second = deepcopy(dual)
    actual = dict(dual_second["multiUpstreamClientAnswers"])
    actual[0x7400] = actual[0x7401] = actual[0x7500] = "203.0.113.81"
    dual_second["multiUpstreamClientAnswers"] = [[key, actual[key]] for key in sorted(actual)]
    check(dual_second); positive += 1

    def bad_wire(name: str, mutate, scenario: str = "multi-upstream-burst", base: dict = baseline) -> None:
        nonlocal negative
        value = deepcopy(base); mutate(value)
        try:
            check(value, scenario)
        except AssertionError:
            negative += 1
        else:
            raise AssertionError(f"Multi-upstream oracle accepted its negative: {name}")

    def replace_query(value: dict, index: int, row: tuple) -> None:
        value["queryDetails"][index] = row; ledger(value)

    bad_wire("cross-source-merge", lambda value: replace_query(value, 1, value["queryDetails"][0]))
    bad_wire("approved-address-from-wrong-provider", lambda value: value["multiUpstreamClientAnswers"].__setitem__(0, [0x7400, "203.0.113.81"]))
    bad_wire("duplicate-client-ID", lambda value: value["multiUpstreamClientAnswers"].__setitem__(1, value["multiUpstreamClientAnswers"][0]))
    bad_wire("unapproved-answer-IP", lambda value: value["multiUpstreamClientAnswers"].__setitem__(0, [0x7400, "203.0.113.99"]))
    bad_wire("warm-cache-changed-provider", lambda value: value["multiUpstreamClientAnswers"].__setitem__(192, [0x7500, "203.0.113.81"]))
    bad_wire("blocked-QNAME-reached-TLS", lambda value: replace_query(value, 0, ("first", "blocked.example.test", 0x7400, first[1])))
    bad_wire("query-peer-unapproved", lambda value: replace_query(value, 0, ("third", "scope.shared.example.test", 0x7400, first[1])))
    bad_wire("cached-ID-reached-TLS", lambda value: replace_query(value, 0, ("first", "scope.shared.example.test", 0x7500, first[1])))
    bad_wire("question-ID-mismatch", lambda value: replace_query(value, 100, ("first", "scope.burst-4.example.test", 0x7605, first[1])))
    bad_wire("fresh-epoch-old-carrier", lambda value: replace_query(value, 352, ("second", "scope.shared.example.test", 0x7701, second[1])))
    for key, bad in (("wirePeak", 33), ("plaintext", 1), ("tlsHandlersActive", 1), ("wireActive", 1),
                     ("errors", ["SSL validation failed"]), ("identityRejected", ["first"]),
                     ("proxyRejected", ["bad authority"]), ("tlsReady", peers[:-1]), ("tlsClosed", peers[:-1]),
                     ("connectFailures", [("127.0.0.1", ports["first"], 503)]), ("scopeCheckpoints", []),
                     ("multiUpstreamClientAnswers", [])):
        bad_wire(key, lambda value, key=key, bad=bad: value.update({key: bad}))
    bad_wire("unapproved-CONNECT", lambda value: value["connects"].__setitem__(0, ("127.0.0.1", 41999)))
    bad_wire("incomplete-physical-close-fence", lambda value: value["scopeCheckpoints"][0].update({"tlsClosed": 1}))
    bad_wire("missing-server-answer", lambda value: value["responseDetails"].pop())
    bad_wire("unproved-same-provider-duplicate", lambda value: (value["queryDetails"].append(value["queryDetails"][0]), ledger(value), evidence(value)))
    bad_wire("two-client-IDs-for-one-coalesced-source", lambda value: replace_query(value, len(value["queryDetails"]) - 1,
             ("second", "scope.shared.example.test", 0x7401, second[1])), base=dual)
    bad_wire("unbound-extra-peer", lambda value: value["carrierBindings"].pop())

    outage = deepcopy(only_second)
    outage_peers = [("second", preflight[1]), second, new_second]
    outage.update({"tls": ["second"] * 3, "tlsPeers": outage_peers,
                   "tlsReady": list(outage_peers), "tlsClosed": list(outage_peers),
                   "preflightACKs": [("second", preflight[1], SOURCE_SCOPE_PREFLIGHT_ACK.hex())],
                   "connects": [("127.0.0.1", ports["second"])] * 3 + [("127.0.0.1", ports["first"])] * 2,
                   "connectFailures": [("127.0.0.1", ports["first"], 503)] * 2})
    outage["scopeCheckpoints"][0].update({"tlsStarted": 2, "tlsReady": 2, "tlsClosed": 2,
                                        "closedPeers": outage_peers[:2], "connectFailures": 1})
    evidence(outage); check(outage, "multi-upstream-connect-failure-burst"); positive += 1
    bad_wire("outage-on-unapproved-port", lambda value: value["connectFailures"].__setitem__(0, ("127.0.0.1", 41999, 503)),
             "multi-upstream-connect-failure-burst", outage)

    canceled = deepcopy(baseline)
    aborted_peer = ("first", ("127.0.0.1", 42999))
    canceled["tlsPeers"].insert(3, aborted_peer)
    canceled["tls"].insert(3, "first"); canceled["tlsClosed"].append(aborted_peer)
    canceled["connects"].append(("127.0.0.1", ports["first"])); canceled["proxyPeers"].append("127.0.0.1")
    evidence(canceled)
    record = canceled["carrierProof"]["records"][3]
    record[5] = 2.5; record[8:13] = ["failure", "cancelled", "HajimiCore.NativeOutboundError", 4, "cancelled"]
    record[17] = True
    canceled["carrierProof"].update({"tlsReady": 5, "typedTLSCancelled": 1})
    canceled["errors"] = ["retained actual fixture EOF error; text never authorizes"]
    canceled["handshakeEOFs"] = [{**canceled["carrierBindings"][3], "errorIndex": 0,
                                  "errorType": "ssl.SSLEOFError", "authenticated": False, "httpPayloadBytes": 0}]
    canceled["scopeCheckpoints"][0].update({"tlsStarted": 4, "tlsReady": 3, "tlsClosed": 4, "connectAttempts": 4,
                                           "closedPeers": [*peers[:3], aborted_peer]})
    check(canceled); positive += 1
    def bad_cancel(name: str, mutate) -> None:
        bad_wire(name, mutate, base=canceled)
    for key, wrong in (("nativeCase", "connection"), ("classification", "other"), ("nativeCase", "crypto"),
                       ("NSErrorDomain", "app.hajimi.cpp-protocol"), ("NSErrorCode", 1),
                       ("firstObserverDeny", 2.4), ("observerAuthenticationCount", 1), ("httpQueries", 1),
                       ("bindingACK", None), ("nativeTLSStarted", 2.9), ("preludeFailure", True),
                       ("boundTypedAbort", False), ("nativeResult", "success")):
        column = CARRIER_PROOF_COLUMNS.index(key)
        bad_cancel("cancel-wash-" + key, lambda value, column=column, wrong=wrong:
                   value["carrierProof"]["records"][3].__setitem__(column, wrong))
    for key, wrong in (("nonce", "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"), ("errorType", "ssl.SSLError"),
                       ("httpPayloadBytes", 1), ("authenticated", True), ("peer", second[1])):
        bad_cancel("unproved-server-cancel-" + key, lambda value, key=key, wrong=wrong:
                   value["handshakeEOFs"][0].update({key: wrong}))
    bad_cancel("missing-bound-eof", lambda value: value.update({"handshakeEOFs": []}))
    bad_cancel("unknown-error-cannot-borrow-eof-text", lambda value: value["errors"].append(value["errors"][0]))
    bad_cancel("missing-actual-native-carrier", lambda value: value["carrierProof"]["records"].pop())

    logical = {"queries": 449, "completedClients": 450, "upstreamLeaders": 352, "mergedClients": 96,
               "cacheHits": 1, "logicalActivePeak": 16, "logicalQueuedPeak": 240,
               "logicalWaitingClientsPeak": 256, "activeLimit": 16, "leaderCapacity": 512,
               "failures": 0, "capacityFailures": 0, "timeoutFailures": 0, "failovers": 16,
               "maximumSuccessfulMilliseconds": 950.0, "perQueryDeadlineMilliseconds": 8000, "upstreamAttempts": 368}
    physical = {"approvedEncryptedProviders": 2, "preflightRawReady": 1, "preflightTLSReady": 1, "preflightDNSQueries": 0,
                "preflightAcknowledgementBytes": len(SOURCE_SCOPE_PREFLIGHT_ACK), "preflightAuthenticatedACK": True,
                "dnsRawCarrierReady": 2, "dnsTLSReady": 2, "tlsFailures": 0, "clientHTTPQueries": 352,
                "encryptedConnectionReuse": 350, "delayedTLSCallbacks": 1, "lateCancelledTLSCallbacks": 1,
                "typedTLSCancelled": 0, "preludeFailures": 0}
    flushed = {"oldTLSCarriersClosedByServer": 3, "newEpochRawCarriers": 2, "newEpochWireQueries": 1,
               "serverCloseFence": True, "logicalActive": 0, "logicalPending": 0}

    def output(one=logical, two=physical, three=flushed) -> str:
        return "\n".join(marker + " " + json.dumps(value) for marker, value in (
            ("DNS-MULTI-UPSTREAM-LOGICAL", one), ("DNS-MULTI-UPSTREAM-PHYSICAL", two),
            ("DNS-MULTI-UPSTREAM-FLUSH", three), ("DNS-MULTI-UPSTREAM-ANSWERS", {
                "fixtureOnly": True, "replyAddresses": baseline["multiUpstreamClientAnswers"]}),
            ("DNS-MULTI-UPSTREAM-CARRIERS", baseline["carrierProof"])))

    validate_source_scope_cli_output(output(), multi_upstream=True, scenario="multi-upstream-burst"); positive += 1
    for category, key, bad in (("logical", "failovers", 0), ("logical", "logicalActivePeak", 32),
                              ("logical", "capacityFailures", 1), ("logical", "perQueryDeadlineMilliseconds", 12000),
                              ("physical", "approvedEncryptedProviders", 1), ("physical", "dnsRawCarrierReady", 65),
                              ("physical", "encryptedConnectionReuse", 287), ("physical", "delayedTLSCallbacks", 0),
                              ("physical", "lateCancelledTLSCallbacks", 0), ("physical", "tlsFailures", 1),
                              ("flush", "serverCloseFence", False), ("flush", "newEpochRawCarriers", 1)):
        one, two, three = deepcopy(logical), deepcopy(physical), deepcopy(flushed)
        {"logical": one, "physical": two, "flush": three}[category][key] = bad
        try:
            validate_source_scope_cli_output(output(one, two, three), multi_upstream=True, scenario="multi-upstream-burst")
        except AssertionError:
            negative += 1
        else:
            raise AssertionError(f"Multi-upstream counter oracle accepted its negative: {category}/{key}")
    trace = Trace()
    value = {"formatVersion": 1, "fixtureOnly": True, "successAssertionsCompleted": False}
    capture_source_scope_timing("earlier failure\nDNS-MULTI-UPSTREAM-TIMING " + json.dumps(value), trace, multi_upstream=True)
    if trace.snapshot()["multiUpstreamTiming"] != value or trace.snapshot()["sourceScopeTiming"] is not None:
        raise AssertionError("Multi-upstream timing was lost or polluted the old single-provider timing")
    positive += 1
    print(f"Multi-upstream wire/counter oracle self-check passed: {positive} positive, {negative} negative; memory only")


def run_functional_witness_oracle_self_test() -> None:
    """Registered lawful cold winners pass; unknown dials/SSL/ID forgeries fail."""
    ports = {"first": 41001, "second": 41002}
    peers = [("first", ("127.0.0.1", 42601)), ("second", ("127.0.0.1", 42602)),
             ("first", ("127.0.0.1", 42603))]
    questions = [("first", "adaptive.cold.example.test", 0x7201, peers[0][1]),
                 ("second", "adaptive.discover.example.test", 0x7202, peers[1][1]),
                 ("second", "adaptive.preferred.example.test", 0x7203, peers[1][1]),
                 ("first", "adaptive.cold.example.test", 0x7206, peers[2][1])]
    observed = {"tls": [label for label, _ in peers], "tlsPeers": peers, "tlsReady": list(peers),
                "tlsClosed": list(peers), "queries": [(label, name) for label, name, _, _ in questions],
                "queryPeers": [(label, name, peer) for label, name, _, peer in questions],
                "queryDetails": questions, "responseDetails": list(questions),
                "connects": [("127.0.0.1", ports[label]) for label, _ in peers],
                "proxyPeers": ["127.0.0.1"] * 3, "identityRejected": [], "proxyRejected": [],
                "plaintext": 0, "errors": [], "tlsHandlersActive": 0, "wireActive": 0, "connectFailures": []}
    witness = {"formatVersion": 1, "fixtureOnly": True, "scenario": "production-success",
               "successAssertionsCompleted": True, "transactions": 6,
               "answers": [[0x7201, "203.0.113.80"], [0x7202, "203.0.113.81"], [0x7203, "203.0.113.81"],
                           [0x7204, "203.0.113.80"], [0x7206, "203.0.113.80"]],
               "logical": {"leaders": 4, "cacheHits": 1, "active": 0, "queued": 0, "pending": 0, "waiting": 0},
               "upstreamAttempts": 4, "failovers": 0, "connectionReuse": 1, "dnsFailures": 0,
               "capacityFailures": 0, "timeoutFailures": 0, "rawReady": 3, "tlsReady": 3,
               "tlsFailures": 0, "wireQueries": 4, "invalidObservations": 0,
               "connectionStage": {"count": 3, "failures": 0, "cancelled": 0},
               "tlsStage": {"count": 3, "failures": 0, "cancelled": 0}}

    def events(winners=(0, 1, 1, 0), hedged: set[int] | None = None,
               primaries: dict[int, int] | None = None) -> str:
        hedged = hedged or set()
        primaries = primaries or {}
        lines = []
        for index, winner in enumerate(winners):
            primary = primaries.get(index, 0 if index in {0, 3} else 1)
            lines.append(f"[HajimiNative] dns adaptive attempt candidate_index={primary} ordinal=1 active=1 budget_ms=750 budget_kind=hedge reason=initial")
            if index in hedged:
                lines.append(f"[HajimiNative] dns adaptive attempt candidate_index={1-primary} ordinal=2 active=2 budget_ms=7250 budget_kind=overall reason=soft-budget")
            lines.append(f"[HajimiNative] dns adaptive response candidate_index={winner} elapsed_ms=20 rcode=0")
            lines.append(f"[HajimiNative] dns adaptive finish elapsed_ms=550 attempts={2 if index in hedged else 1} reason=answer rcode=0")
        return "\n".join(lines)

    def check(value: dict, proof: dict = witness, debug: str | None = None) -> None:
        trace = Trace()
        capture_functional_witness("DNS-ADAPTIVE-FUNCTIONAL " + json.dumps(proof) + "\n" + (debug or events()),
                                   trace, "production-success")
        value = deepcopy(value)
        value["functionalWitness"] = trace.snapshot()["functionalWitness"]
        validate_functional_success_trace(value, True, ports)

    positive = negative = 0
    check(observed); positive += 1

    def consistent(value: dict) -> None:
        value["queries"] = [(label, name) for label, name, _, _ in value["queryDetails"]]
        value["queryPeers"] = [(label, name, peer) for label, name, _, peer in value["queryDetails"]]
        value["responseDetails"] = list(value["queryDetails"])

    discovery = deepcopy(observed)
    discovery["queryDetails"].insert(1, ("first", "adaptive.discover.example.test", 0x7202, peers[0][1]))
    consistent(discovery)
    discovery_witness = deepcopy(witness)
    discovery_witness.update({"upstreamAttempts": 5, "failovers": 1, "connectionReuse": 2, "wireQueries": 5})
    discovery_debug = events(hedged={1}, primaries={1: 0})
    # Both providers own this exact ID only after their actual registrations;
    # a cancelled loser need not manage to send its delayed server response.
    check(discovery, discovery_witness, discovery_debug); positive += 1
    discovery["responseDetails"].remove(discovery["queryDetails"][1])
    check(discovery, discovery_witness, discovery_debug); positive += 1

    cold = deepcopy(observed)
    cold["queryDetails"].insert(1, ("second", "adaptive.cold.example.test", 0x7201, peers[1][1]))
    consistent(cold)
    cold_witness = deepcopy(witness)
    cold_witness.update({"upstreamAttempts": 5, "failovers": 1, "connectionReuse": 2, "wireQueries": 5})
    cold_witness["answers"][0][1] = cold_witness["answers"][3][1] = "203.0.113.81"
    check(cold, cold_witness, events((1, 1, 1, 0), {0})); positive += 1
    fresh = deepcopy(observed)
    new_second = ("second", ("127.0.0.1", 42604))
    for name in ("tlsPeers", "tlsReady", "tlsClosed"):
        fresh[name].append(new_second)
    fresh["tls"].append("second")
    fresh["connects"].append(("127.0.0.1", ports["second"]))
    fresh["proxyPeers"].append("127.0.0.1")
    fresh["queryDetails"].append(("second", "adaptive.cold.example.test", 0x7206, new_second[1]))
    consistent(fresh)
    fresh_witness = deepcopy(witness)
    fresh_witness.update({"upstreamAttempts": 5, "failovers": 1, "rawReady": 4, "tlsReady": 4, "wireQueries": 5})
    fresh_witness["connectionStage"]["count"] = fresh_witness["tlsStage"]["count"] = 4
    fresh_witness["answers"][4][1] = "203.0.113.81"
    check(fresh, fresh_witness, events((0, 1, 1, 1), {3})); positive += 1

    def bad(name: str, mutate, *, proof: dict = witness, debug: str | None = None,
            baseline: dict = observed) -> None:
        nonlocal negative
        value = deepcopy(baseline); mutate(value)
        try:
            check(value, proof, debug)
        except AssertionError:
            negative += 1
        else:
            raise AssertionError(f"Functional witness oracle accepted its negative: {name}")

    def replace(value: dict, index: int, row: tuple) -> None:
        value["queryDetails"][index] = row; consistent(value)

    bad("discover-primary-not-registered", lambda value: None, baseline=discovery)
    bad("discover-winner-response-missing", lambda value: value["responseDetails"].remove(
        ("second", "adaptive.discover.example.test", 0x7202, peers[1][1])),
        proof=discovery_witness, debug=discovery_debug, baseline=discovery)
    bad("warm-cache-ID-reached-wire", lambda value: replace(value, 0, ("first", "adaptive.cold.example.test", 0x7204, peers[0][1])))
    bad("blocked-QNAME-reached-wire", lambda value: replace(value, 0, ("first", "blocked.example.test", 0x7201, peers[0][1])))
    bad("wrong-QNAME-same-ID", lambda value: replace(value, 0, ("first", "adaptive.identity.example.test", 0x7201, peers[0][1])))
    bad("unregistered-provider", lambda value: replace(value, 0, ("second", "adaptive.cold.example.test", 0x7201, peers[1][1])))
    bad("unobserved-peer", lambda value: replace(value, 0, ("first", "adaptive.cold.example.test", 0x7201, ("127.0.0.1", 42699))))
    bad("flush-old-peer", lambda value: replace(value, 3, ("first", "adaptive.cold.example.test", 0x7206, peers[0][1])))
    for key, wrong in (("proxyRejected", ["Truncated CONNECT request"]), ("errors", ["SSL validation failed"]),
                       ("plaintext", 1), ("identityRejected", ["first"]), ("tlsReady", peers[:-1]),
                       ("tlsClosed", peers[:-1]), ("tlsHandlersActive", 1), ("wireActive", 1)):
        bad(key, lambda value, key=key, wrong=wrong: value.update({key: wrong}))
    bad("server-winning-answer-missing", lambda value: value["responseDetails"].pop())
    bad("CONNECT-unapproved-port", lambda value: value["connects"].__setitem__(0, ("127.0.0.1", 41999)))
    for key, wrong in (("failovers", 1), ("capacityFailures", 1), ("timeoutFailures", 1), ("rawReady", 4),
                       ("fixtureOnly", False), ("successAssertionsCompleted", False)):
        proof = deepcopy(witness); proof[key] = wrong
        bad(key, lambda value: None, proof=proof)
    proof = deepcopy(witness); proof["answers"][3][1] = "203.0.113.81"
    bad("warm-answer-changed-winner", lambda value: None, proof=proof)
    proof = deepcopy(witness); proof["connectionStage"]["cancelled"] = 4
    bad("invented-native-receipt", lambda value: None, proof=proof)
    for name, text in (("missing-attempt-ledger", "unrelated diagnostic"),
                       ("post-finish-dial", events() + "\n[HajimiNative] dns adaptive attempt candidate_index=1 ordinal=2 active=2 budget_ms=7000 budget_kind=overall reason=soft-budget"),
                       ("unapproved-candidate-index", events().replace("candidate_index=0", "candidate_index=2", 1)),
                       ("more-than-two-live", events().replace("active=1", "active=3", 1)),
                       ("over-original-deadline", events().replace("elapsed_ms=550", "elapsed_ms=8000", 1))):
        bad(name, lambda value: None, debug=text)
    # This peer sent literally no bytes, selected no resolver and reached no
    # upstream socket. Exactly one registered soft loser and actual pre-TLS
    # cancelled callback receipt account for its one accepted/closed handler.
    cancellation = deepcopy(observed)
    cancellation.update({"approvedProxyEndpoint": ("127.0.0.1", 41003), "proxyHandlersActive": 0,
                         "elapsedSeconds": 3.0})
    cancellation["proxyPeers"].append("127.0.0.1")
    normal_rows = [{"ordinal": index, "peer": ("127.0.0.1", 42701 + index),
                    "proxyEndpoint": ("127.0.0.1", 41003), "acceptedSeconds": 0.1 * (index + 1),
                    "closedSeconds": 1.9, "receivedBytes": 128, "cleanEOF": False,
                    "connectHeaderComplete": True, "targetPort": ports[label], "upstreamOpened": True}
                   for index, (label, _) in enumerate(peers)]
    empty_row = {"ordinal": 3, "peer": ("127.0.0.1", 42704), "proxyEndpoint": ("127.0.0.1", 41003),
                 "acceptedSeconds": 1.95, "closedSeconds": 1.951, "receivedBytes": 0,
                 "cleanEOF": True, "connectHeaderComplete": False, "targetPort": None,
                 "upstreamOpened": False, "preConnectEmptyEOF": True}
    cancellation["proxyConnections"] = normal_rows + [empty_row]
    cancel_witness = deepcopy(witness)
    cancel_witness.update({"upstreamAttempts": 5, "failovers": 1,
                           "connectionStage": {"count": 4, "failures": 0, "cancelled": 1}})
    cancel_debug = events((0, 1, 1, 0), {3})
    check(cancellation, cancel_witness, cancel_debug); positive += 1

    def bad_cancel(name: str, mutate, proof: dict = cancel_witness, debug: str = cancel_debug) -> None:
        nonlocal negative
        value = deepcopy(cancellation); mutate(value)
        try:
            check(value, proof, debug)
        except AssertionError:
            negative += 1
        else:
            raise AssertionError(f"Pre-CONNECT oracle accepted its negative: {name}")

    for key, wrong in (("receivedBytes", 1), ("receivedBytes", False), ("cleanEOF", False),
                       ("connectHeaderComplete", True), ("targetPort", ports["second"]),
                       ("upstreamOpened", True), ("proxyEndpoint", ("127.0.0.1", 41999)),
                       ("peer", ("127.0.0.2", 42704)), ("closedSeconds", None),
                       ("closedSeconds", 0.5), ("closedSeconds", float("inf"))):
        bad_cancel(key, lambda value, key=key, wrong=wrong: value["proxyConnections"][-1].update({key: wrong}))
    bad_cancel("handler-not-drained", lambda value: value.update({"proxyHandlersActive": 1}))
    bad_cancel("duplicated-observed-peer", lambda value: value["proxyConnections"][-1].update({"peer": normal_rows[0]["peer"]}))
    bad_cancel("unapproved-listener", lambda value: value.update({"approvedProxyEndpoint": ("127.0.0.2", 41003)}))
    bad_cancel("counter-ledger-hides-peer", lambda value: value["proxyPeers"].pop())
    bad_cancel("still-reports-SSL-error", lambda value: value.update({"errors": ["SSL EOF"]}))
    bad_cancel("post-finish-new-dial", lambda value: None, debug=cancel_debug + "\n[HajimiNative] dns adaptive attempt candidate_index=1 ordinal=2 active=2 budget_ms=7000 budget_kind=overall reason=soft-budget")
    proof = deepcopy(cancel_witness); proof["connectionStage"]["cancelled"] = 0
    bad_cancel("cancel-is-not-a-callback-ACK", lambda value: None, proof=proof)
    proof = deepcopy(cancel_witness); proof["connectionStage"]["count"] = 5
    bad_cancel("dial-receipts-do-not-match", lambda value: None, proof=proof)
    proof = deepcopy(cancel_witness); proof.update({"upstreamAttempts": 4, "failovers": 0, "connectionReuse": 0})
    bad_cancel("no-registered-soft-hedge-loser", lambda value: None, proof=proof, debug=events())
    print(f"Functional registered-winner wire/counter oracle self-check passed: {positive} positive, {negative} negative; memory only")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path(".build/x86_64-apple-macosx/release/Hajimi"))
    parser.add_argument("--protection", choices=("true", "false", "both"), default="both")
    scenarios = ("failure", "success", "identity-failure", "production-success", "production-identity-failure",
                 "source-scope-burst", "multi-upstream-burst", "multi-upstream-connect-failure-burst")
    parser.add_argument("--scenario", choices=(*scenarios, "all"), default="all")
    parser.add_argument("--oracle-self-test", action="store_true", help="Memory-only wire-oracle regression; no sockets or app")
    arguments = parser.parse_args()
    if arguments.oracle_self_test:
        run_oracle_self_test()
        return 0
    binary = arguments.binary.resolve()
    if not binary.is_file():
        parser.error("--binary must name the existing release executable")
    values = [True, False] if arguments.protection == "both" else [arguments.protection == "true"]
    scenarios = scenarios if arguments.scenario == "all" else [arguments.scenario]
    try:
        for value in values:
            for scenario in scenarios:
                run(binary, value, scenario)
        return 0
    except (AssertionError, OSError, subprocess.TimeoutExpired) as error:
        print(f"FAILED: {error}", file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
