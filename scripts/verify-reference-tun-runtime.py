"""Independent bounded replay of original reference TUN research artifacts.

No producer imports, device execution, identities or provider diagnostics.
"""
import argparse
import html
import json
import os
from pathlib import Path
import re
import stat
import time
import xml.etree.ElementTree as ET

CLASS = 'com.httpfreekit.interop.DraftReferenceTunInteropTest'
METHODS = ('selectedUidHttpReachesReferenceOriginThroughTun',
           'selectedUidH1HttpsReachesReferenceOriginThroughTun')
PHASES = ('input-consumed strict-csr-reserved awaiting-host-approval '
          'credential-saved-reloaded authenticated-ca-fetched vpn-consent-granted '
          'tun-native-active selected-uid-route-observed traffic-command-started '
          'traffic-response-validated local-stream-drained gateway-complete-acknowledged '
          'capture-stop-joined non-vpn-route-observed traffic-worker-joined owned-state-forgotten').split()
FLAGS = ('credentialSavedReloaded keyNonexportable originalCredentialUnchanged authenticatedCaFetched '
         'separateTrafficUid vpnConsentGranted selectedUidVpnObserved tunAndNativeObserved foregroundNotificationObserved '
         'requestBodyValidated responseBodyValidated outputHalfClosed strictResponseEof socketClosed localStreamsDrained '
         'hostCompleteAcknowledged captureStopped tunClosed nativeStopJoined configurationAbsent lifecycleJoined factoryClosed '
         'nonVpnRouteObserved trafficWorkerJoined consentUiDestroyed ownedStateAbsent').split()
ZEROS = ('directTcpFlows udpTargets udp443Drops protectFailures bindFailures activeFlows ownedSockets pendingOpens liveWorkers '
         'factoryPendingOpens factoryPendingCalls retainedTransports factoryLiveWorkers streamLeases chargedBytes pendingIngressBytes '
         'backendOutputBytes backendIncomingBytes').split()
GUARDS = 'protectAttempts protectSuccesses bindAttempts bindSuccesses'.split()
HOST_TRUE = ('streamResourcesReleased clientEofEmitted gatewayEofEmitted webSocketClosed close1000Acknowledged '
             'sessionLease requestMatched responseMatched originModeMatched').split()
HOST_ZERO = ('chargedBytes controlChargedBytes chargedFrames streamLeases pendingIngressBytes activeOwners activeSockets '
             'activeRequests rejectedPrefaces').split()
RESOURCE_FLAGS = ('ownedReversesAbsent privateDirectoryRemoved gatewayJoined backendJoined assetsJoined '
                  'ownedCommandsClosed ownedCommandGroupsClosed').split()
COMMAND = dict(exitCode=0, signal=None, reason=None, closeObserved=True, processGroupClosed=True)
WORKER = dict.fromkeys('admissionClosed listenersClosed storeClosed issuerChildrenJoined'.split(), True)
WORKER.update(dict.fromkeys('activeSockets pendingCallbacks pendingTimers issuerJobs signerGroups workers'.split(), 0))
PROCESS = dict(closeObserved=True, exitCode=0, signal=None, processGroupJoined=True, stdoutJoined=True,
               stderrJoined=True, stdinJoined=True, pendingWrites=0, pendingRequests=0, forced=False, failure=None)
PACKAGE_FLAGS = 'initiallyAbsent installAttempted installed uninstallConfirmed absentAfterCleanup'.split()
PERMISSIONS = 'interopLocalNetwork trafficLocalNetwork interopNotification'.split()
PATHS = {
    'runtime': 'tools/transport-spike/android/build/outputs/androidTest-results/reference-tun/debug/runtime.json',
    'xml': 'tools/transport-spike/android/build/outputs/androidTest-results/reference-tun/debug/TEST-reference-tun-research.xml',
    'html': 'tools/transport-spike/android/build/reports/androidTests/reference-tun/debug/index.html',
    'host': 'build/reports/reference-tun/host-cleanup.json',
}
CAPS = dict(runtime=65536, xml=131072, html=131072, host=16384)
HTML_START = '<!doctype html><html lang="en"><meta charset="utf-8"><title>Reference TUN research</title><body><pre>'
HTML_END = '</pre></body></html>\n'


class InvalidEvidence(ValueError):
    """Only a fixed diagnostic may cross the CLI boundary."""


def require(condition):
    if not condition:
        raise InvalidEvidence('invalid_reference_tun_evidence')


def exact(value, keys):
    require(type(value) is dict and set(value) == set(keys))


def integer(value, low=0, high=131072):
    require(type(value) is int and low <= value <= high)


def equal(value, expected):
    # Unlike Python equality, this rejects true in place of 1 (including nested data).
    require(type(value) is type(expected))
    if type(expected) is dict:
        exact(value, expected)
        for key in expected:
            equal(value[key], expected[key])
    elif type(expected) is list:
        require(len(value) == len(expected))
        for actual, wanted in zip(value, expected):
            equal(actual, wanted)
    else:
        require(value == expected)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def load_json(data):
    require(type(data) is bytes and 0 < len(data) <= max(CAPS.values()))
    # Bound nesting before the JSON decoder can allocate a deeply recursive tree.
    # Braces inside escaped JSON strings are data, not structure.
    depth = 0
    quoted = escaped = False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            require(depth <= 32)
        elif byte in (93, 125):
            depth -= 1
            require(depth >= 0)
    def number(value):
        require(re.fullmatch(r'-?(?:0|[1-9][0-9]{0,15})', value) is not None)
        return int(value)
    def invalid(_):
        raise InvalidEvidence('invalid_reference_tun_evidence')
    try:
        return json.loads(data.decode('utf-8', 'strict'), object_pairs_hook=unique,
                          parse_int=number, parse_float=invalid, parse_constant=invalid)
    except (ValueError, UnicodeError, RecursionError):
        raise InvalidEvidence('invalid_reference_tun_evidence') from None


def observation(https, guard=2):
    result = dict.fromkeys(FLAGS, True)
    result.update(dict.fromkeys(ZEROS, 0))
    result.update(dict.fromkeys(GUARDS, guard))
    result.update(version=1, sessionLease=False, trafficAttempts=1, selectedPackageCount=1,
                  interceptedTcpFlows=1, responseBodyBytes=81, tlsUsed=https, tlsPeerVerified=https)
    return result


def host_completion(https):
    result = dict.fromkeys(HOST_TRUE, True)
    result.update(dict.fromkeys(HOST_ZERO, 0))
    result.update(phase='complete', streamLease=False, ownersCreated=1, ownersClosed=1, upstreamDials=1,
                  interceptedHttpRequests=int(not https), upstreamHttpRequests=int(not https),
                  interceptedHttpsRequests=int(https), upstreamHttpsRequests=int(https),
                  interceptionTlsHandshakes=int(https), upstreamTlsHandshakes=int(https),
                  requestBytes=4096, responseBytes=81)
    return result


def transfer(value, ack):
    keys = ['byteCount', 'inputBytes', 'inputFinished', 'inputClosed', 'command']
    exact(value, keys + (['published', 'absentAfterMethod'] if ack else ['inputAbsentAfterMethod']))
    integer(value['byteCount'], 1, 128 if ack else 16384)
    equal(value, dict(byteCount=value['byteCount'], inputBytes=value['byteCount'], inputFinished=True,
                      inputClosed=True, command=COMMAND,
                      **(dict(published=True, absentAfterMethod=True) if ack else dict(inputAbsentAfterMethod=True))))
    if ack:
        integer(value['byteCount'], 34, 34)  # FREEKIT-REFERENCE-TUN-COMPLETE-V1\n


def clock(value, started, now):
    exact(value, ['deviceEpochSeconds', 'hostBeforeMillis', 'hostAfterMillis', 'roundTripMillis', 'lowerBoundMillis', 'upperBoundMillis'])
    integer(value['deviceEpochSeconds'], 946684800, 4102444800)
    for key in ['hostBeforeMillis', 'hostAfterMillis']:
        integer(value[key], 946684800000, 4102444800000)
    for key in ['lowerBoundMillis', 'upperBoundMillis', 'roundTripMillis']:
        integer(value[key], -9007199254740991, 9007199254740991)
    before, after, device = value['hostBeforeMillis'], value['hostAfterMillis'], value['deviceEpochSeconds'] * 1000
    require(started * 1000 - 2000 <= before <= after <= (now + 10) * 1000)
    require(value['roundTripMillis'] == after - before and 0 <= after - before <= 2000)
    require(value['lowerBoundMillis'] == device - after >= -2000)
    require(value['upperBoundMillis'] == device + 999 - before <= 2000)


def verify(runtime, host, xml_bytes, html_bytes, source, api, started, now=None):
    now = time.time() if now is None else now
    require(type(source) is str and re.fullmatch('[0-9a-f]{40}', source) is not None)
    require(type(api) is int and api in (26, 37))
    integer(started, 946684800, 4102444800)
    require(started <= now + 60)
    exact(runtime, ['format', 'revision', 'source', 'api', 'clock', 'methods', 'apkSetup', 'cleanup', 'problems'])
    equal(runtime['format'], 'http-freekit-reference-tun-runtime')
    equal(runtime['revision'], 1); equal(runtime['api'], api)
    equal(runtime['source'], dict(commit=source, trackedDirty=False)); equal(runtime['problems'], [])
    clock(runtime['clock'], started, now)
    require(type(runtime['methods']) is list and len(runtime['methods']) == 2)
    for index, item in enumerate(runtime['methods']):
        exact(item, ['invocation', 'input', 'approval', 'host', 'ack', 'resources'])
        invocation = item['invocation']
        exact(invocation, ['method', 'state', 'actualStarted', 'actualCompleted', 'terminalCount', 'terminalCode',
                           'phases', 'command', 'problems', 'failureType', 'frames', 'observation', 'failure'])
        facts = invocation['observation']
        require(type(facts) is dict and 'protectAttempts' in facts)
        guard = facts['protectAttempts']; integer(guard, 2)
        equal(invocation, dict(method=METHODS[index], state='passed', actualStarted=1, actualCompleted=1,
                               terminalCount=1, terminalCode=-1, phases=PHASES, command=COMMAND, problems=[],
                               failureType=None, frames=[], observation=observation(index == 1, guard), failure=None))
        transfer(item['input'], False); transfer(item['ack'], True)
        equal(item['approval'], dict(registered=True, livePhaseObserved=True, requested=True, completed=True))
        # CONTROL remains leased here: COMPLETE is the natural STREAM barrier BEFORE ACK/Stop.
        equal(item['host'], dict(completion=host_completion(index == 1), livePhaseObserved=True,
                                 completeObservedBeforeAck=True, androidAckPhaseObserved=True))
        resources = item['resources']
        equal(resources, dict(gateway=WORKER, process=PROCESS, reverseCommands=[COMMAND] * 3,
                              **dict.fromkeys(RESOURCE_FLAGS, True)))
        # gatewayJoined is the producer's aggregate of post-close sessionLeases==0;
        # that raw final counter is not present in revision 1's gateway projection.
    setup = runtime['apkSetup']
    expected_packages = []
    for package in ['com.httpfreekit.capturetest', 'com.httpfreekit.capturetraffic']:
        expected_packages.append(dict(package=package, **dict.fromkeys(PACKAGE_FLAGS, True),
                                      installCommand=COMMAND, forceStopCommand=COMMAND, uninstallCommand=COMMAND))
    equal(setup, dict(sameSigner=True, controlTrafficGranted=True, packages=expected_packages,
                     permissions=dict(mode='not_required' if api == 26 else 'owned_ci_grant',
                                      **dict.fromkeys(PERMISSIONS, None if api == 26 else COMMAND))))
    equal(runtime['cleanup'], dict(forceStopCommand=COMMAND, uninstallCommand=COMMAND, uninstallConfirmed=True,
                                   packageAbsentAfterCleanup=True, ownedCommandsClosed=True, ownedCommandGroupsClosed=True))
    exact(host, ['format', 'revision', 'sourceCommit', 'api', 'driverExitCode', 'emulatorStarted', 'stopAttempted',
                 'stopExitCode', 'terminationObserved', 'joinObserved', 'emulatorExitCode'])
    integer(host['stopExitCode'], 0, 255); integer(host['emulatorExitCode'], 0, 255)
    require(host['emulatorExitCode'] != 127)
    equal(host, dict(format='http-freekit-reference-tun-host-cleanup', revision=1, sourceCommit=source, api=api,
                     driverExitCode=0, emulatorStarted=True, stopAttempted=True, stopExitCode=host['stopExitCode'],
                     terminationObserved=True, joinObserved=True, emulatorExitCode=host['emulatorExitCode']))
    verify_xml(xml_bytes)
    verify_html(html_bytes, runtime)
    return 2


def verify_xml(data):
    require(type(data) is bytes and 0 < len(data) <= CAPS['xml'])
    # Reject DTDs/entities (including alternate encodings), processing instructions,
    # comments and any extra markup by checking the exact finite producer document.
    expected = '<?xml version="1.0" encoding="UTF-8"?>\n'
    expected += f'<testsuite name="{CLASS}" tests="2" failures="0" errors="0" skipped="0">\n'
    expected += '\n'.join(f'<testcase classname="{CLASS}" name="{method}" time="0"></testcase>' for method in METHODS)
    expected += '\n</testsuite>\n'
    require(data == expected.encode('ascii'))
    root = ET.fromstring(data)
    require(root.tag == 'testsuite' and len(root) == 2)


def verify_html(data, runtime):
    require(type(data) is bytes and 0 < len(data) <= CAPS['html'])
    text = data.decode('utf-8', 'strict')
    require(text.startswith(HTML_START) and text.endswith(HTML_END))
    payload = text[len(HTML_START):-len(HTML_END)]
    decoded = html.unescape(payload)
    escaped = decoded.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&apos;')
    require(payload == escaped)
    equal(load_json(decoded.encode('utf-8')), runtime)


def read_file(path, cap, started):
    """Open each ancestor without following links; bound reads and detect replacement."""
    require(path.is_absolute() and '..' not in path.parts)
    directory = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    descriptor = None
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory); directory = child
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= cap)
        require(started - 2 <= before.st_mtime <= time.time() + 10)
        data = bytearray()
        while len(data) <= cap:
            chunk = os.read(descriptor, min(8192, cap + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
        current = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        signature = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        require(signature(before) == signature(after) == signature(current) and len(data) == before.st_size)
        return bytes(data)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory)


def main():
    class SafeArguments(argparse.ArgumentParser):
        def error(self, message):
            print('Reference TUN verification failed.')
            raise SystemExit(2)
    parser = SafeArguments(description='Independently replay original reference TUN research artifacts')
    parser.add_argument('--source', required=True)
    parser.add_argument('--api', required=True, type=int, choices=[26, 37])
    parser.add_argument('--started', required=True, type=int)
    for name in PATHS:
        parser.add_argument('--' + name)
    args = parser.parse_args()
    try:
        require(re.fullmatch('[0-9a-f]{40}', args.source) is not None)
        integer(args.started, 946684800, 4102444800); require(args.started <= time.time() + 60)
        root = Path(__file__).resolve().parent.parent
        paths = {name: Path(getattr(args, name)) if getattr(args, name) else root / default for name, default in PATHS.items()}
        require(len(set(paths.values())) == 4)
        files = {name: read_file(path, CAPS[name], args.started) for name, path in paths.items()}
        count = verify(load_json(files['runtime']), load_json(files['host']), files['xml'], files['html'],
                       args.source, args.api, args.started)
        print(f'Reference TUN verified: API {args.api}, {count} actual methods, owned cleanup complete.')
        return 0
    except (InvalidEvidence, OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        print('Reference TUN verification failed.')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
