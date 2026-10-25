"""Independent finite C1 acceptance gate. Never prints provider messages or report payloads."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import time
import xml.etree.ElementTree as ET

CLASS = 'com.httpfreekit.capturetest.CapturePolicyInteropTest'
CASES = [
    ('selectedTcpUsesTunAndNonselectedUidBypasses', 'uid', 2, dict(SelectedUidStable='true', SelectedHttp='1', SelectedOpaque='1', BypassHttp='1', BypassOpaque='1', MissingAuthRejected='true', WrongAuthRejected='true')),
    ('directTcpUdpDnsAndUdp443Policy', 'direct', 1, dict(DirectTcp='1', Udp='1', Dns='1', Udp443PositiveControl='true', Udp443NoDelivery='true', Udp443DropObserved='true')),
    ('selectedIpv6UsesTun', 'ipv6', 1, dict(OriginalIpv6Validated='true', InterceptedIpv6='1')),
    ('stopJoinsCaptureAndAllowsFreshStart', 'stop', 2, dict(HeldRequestObserved='true', HeldRequestInterrupted='true', HeldFixtureCleanupJoined='true', FreshStartForwards='true')),
    ('protectAndBindFailuresFailClosed', 'guards', 2, dict(ProtectRefused='true', BindRefused='true', NoFlowConnect='true', RefusedSocketsClosed='true', RouteRetainedUntilStop='true')),
]
PERMISSION = ('localNetworkDenialPreventsTun', 'permission', 0, {})
FLOW = ['directHttp', 'directOpaque', 'directTcp', 'udp', 'dns', 'udp443', 'interceptedHttp', 'interceptedOpaque', 'interceptedIpv6', 'heldRequestsClosed', 'heldCloseRequests', 'tcpConnections', 'udpDatagrams']
CUMULATIVE = FLOW + ['uploadBytes', 'downloadBytes', 'invalidRequests']
OWNED = ['activeSockets', 'pendingCallbacks', 'timers', 'listeners', 'heldConnections']
SNAPSHOT = set(CUMULATIVE + OWNED + ['closed'])


class InvalidCapture(ValueError):
    pass


def require(condition):
    if not condition:
        raise InvalidCapture('invalid_capture_evidence')


def exact(value, names):
    require(type(value) is dict and set(value) == set(names))


def integer(value, low=0, high=10_000_000):
    require(type(value) is int and low <= value <= high)


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value)
        value[key] = item
    return value


def load_json(data):
    try:
        def bounded_integer(value):
            require(re.fullmatch(r'-?(?:0|[1-9][0-9]{0,15})', value) is not None)
            return int(value)
        return json.loads(data.decode('utf-8', errors='strict'), object_pairs_hook=unique,
                          parse_int=bounded_integer,
                          parse_constant=lambda _: (_ for _ in ()).throw(InvalidCapture()))
    except (ValueError, UnicodeError, RecursionError):
        raise InvalidCapture('invalid_capture_json') from None


def facts(definition, api, dialog):
    _, scenario, starts, extra = definition
    require(dialog in ('true', 'false'))
    common = dict(captureVersion='1', captureScenario=scenario, captureConsentGranted='true', captureConsentDialogObserved=dialog)
    if definition == PERMISSION:
        return dict(common, captureLocalNetworkPermission='denied', captureFactoryCalls='0', captureTunEstablished='false', captureCaptureOwnerAbsent='true', captureStopJoined='true')
    return dict(common, captureStarts=str(starts), captureStops=str(starts), captureLocalNetworkPermission='granted' if api == 37 else 'not_required',
                captureTunAndNativeObserved='true', captureAllStopsJoined='true', captureTrafficWorkerJoined='true', captureNotificationObserved='true',
                **{'capture' + key: value for key, value in extra.items()})


def snapshot(value, closed):
    exact(value, SNAPSHOT)
    require(value['closed'] is closed)
    for key in SNAPSHOT - {'closed'}:
        integer(value[key])


def verify(runtime, host, xml_bytes, source, api):
    require(re.fullmatch('[0-9a-f]{40}', source) is not None and api in (26, 37))
    exact(runtime, ['format', 'revision', 'source', 'api', 'clock', 'permissionSetup', 'methods', 'cleanup', 'problems', 'accepted'])
    require(runtime['format'] == 'http-freekit-capture-runtime' and type(runtime['revision']) is int and runtime['revision'] == 1 and type(runtime['api']) is int and runtime['api'] == api and runtime['accepted'] is True and runtime['problems'] == [])
    exact(runtime['source'], ['commit', 'trackedDirty'])
    require(runtime['source'] == {'commit': source, 'trackedDirty': False} and runtime['source']['trackedDirty'] is False)
    clock = runtime['clock']
    exact(clock, ['deviceEpochSeconds', 'hostBeforeMillis', 'hostAfterMillis', 'roundTripMillis', 'lowerBoundMillis', 'upperBoundMillis'])
    for key, value in clock.items():
        integer(value, -2000 if key.endswith('BoundMillis') else 0, 4_102_444_800_000)
    require(946_684_800 <= clock['deviceEpochSeconds'] <= 4_102_444_800 and 946_684_800_000 <= clock['hostBeforeMillis'] <= clock['hostAfterMillis'])
    require(clock['roundTripMillis'] == clock['hostAfterMillis'] - clock['hostBeforeMillis'] <= 2000)
    require(clock['lowerBoundMillis'] == clock['deviceEpochSeconds'] * 1000 - clock['hostAfterMillis'] >= -2000)
    require(clock['upperBoundMillis'] == clock['deviceEpochSeconds'] * 1000 + 999 - clock['hostBeforeMillis'] <= 2000)
    permission = runtime['permissionSetup']
    exact(permission, ['required', 'mode', 'hostGrantExitCode', 'trafficGrantExitCode'])
    require(permission == ({'required': True, 'mode': 'owned_ci_grant', 'hostGrantExitCode': 0, 'trafficGrantExitCode': 0} if api == 37 else {'required': False, 'mode': 'not_required', 'hostGrantExitCode': None, 'trafficGrantExitCode': None}))
    require(permission['required'] is (api == 37))
    if api == 37:
        integer(permission['hostGrantExitCode'], 0, 0); integer(permission['trafficGrantExitCode'], 0, 0)
    definitions = ([PERMISSION] if api == 37 else []) + CASES
    require(type(runtime['methods']) is list and len(runtime['methods']) == len(definitions))
    previous = dict.fromkeys(CUMULATIVE, 0)
    for index, (entry, definition) in enumerate(zip(runtime['methods'], definitions)):
        exact(entry, ['invocation', 'receiversBefore', 'receiversAfter'])
        invocation = entry['invocation']
        exact(invocation, ['method', 'state', 'actualStarted', 'actualCompleted', 'terminalCount', 'terminalCode', 'observation', 'failure', 'command', 'problems'])
        require(invocation['method'] == definition[0] and invocation['state'] == 'passed' and invocation['failure'] is None and invocation['problems'] == [])
        for key in ['actualStarted', 'actualCompleted', 'terminalCount']:
            integer(invocation[key], 1, 1)
        integer(invocation['terminalCode'], -1, -1)
        command = invocation['command']
        exact(command, ['exitCode', 'signal', 'closeObserved', 'processGroupClosed', 'reason'])
        require(command == {'exitCode': 0, 'signal': None, 'closeObserved': True, 'processGroupClosed': True, 'reason': None})
        integer(command['exitCode'], 0, 0); require(command['closeObserved'] is True and command['processGroupClosed'] is True)
        observation = invocation['observation']
        require(type(observation) is dict)
        expected = facts(definition, api, observation.get('captureConsentDialogObserved'))
        require(observation == expected and (index != 0 or observation['captureConsentDialogObserved'] == 'true'))
        before, after = entry['receiversBefore'], entry['receiversAfter']
        snapshot(before, False); snapshot(after, False)
        require(all(before[key] == previous[key] for key in CUMULATIVE))
        expected_delta = {} if definition == PERMISSION else [dict(interceptedHttp=1, interceptedOpaque=1, directHttp=1, directOpaque=1, tcpConnections=4), dict(directTcp=1, udp=1, dns=1, udp443=1, tcpConnections=1, udpDatagrams=3), dict(interceptedIpv6=1, tcpConnections=1), dict(heldRequestsClosed=1, heldCloseRequests=1, interceptedHttp=1, tcpConnections=2), {}][CASES.index(definition)]
        require(all(after[key] - before[key] == expected_delta.get(key, 0) for key in FLOW) and after['invalidRequests'] == before['invalidRequests'] and after['heldConnections'] == 0)
        if definition[1] == 'stop':
            require(all(after[key] == 0 for key in ['activeSockets', 'pendingCallbacks', 'timers']))
        previous = after
    cleanup = runtime['cleanup']
    exact(cleanup, ['forceStopExitCodes', 'uninstallExitCodes', 'packagesAbsent', 'ownedCommandsClosed', 'ownedCommandGroupsClosed', 'receivers'])
    for key in ['packagesAbsent', 'ownedCommandsClosed', 'ownedCommandGroupsClosed']:
        require(cleanup[key] is True)
    for key in ['forceStopExitCodes', 'uninstallExitCodes']:
        require(type(cleanup[key]) is list and len(cleanup[key]) == 4)
        for code in cleanup[key]:
            integer(code, 0, 0)
    snapshot(cleanup['receivers'], True)
    require(all(cleanup['receivers'][key] == 0 for key in OWNED) and all(cleanup['receivers'][key] == previous[key] for key in CUMULATIVE))
    exact(host, ['format', 'revision', 'sourceCommit', 'api', 'driverExitCode', 'emulatorStarted', 'stopAttempted', 'stopExitCode', 'terminationObserved', 'joinObserved', 'emulatorExitCode'])
    require(host['format'] == 'http-freekit-capture-host-cleanup' and host['revision'] == 1 and host['sourceCommit'] == source and host['api'] == api)
    for key in ['revision', 'api', 'driverExitCode', 'stopExitCode', 'emulatorExitCode']:
        integer(host[key], 0, 255)
    require(host['driverExitCode'] == 0 and host['emulatorExitCode'] != 127)
    require(all(host[key] is True for key in ['emulatorStarted', 'stopAttempted', 'terminationObserved', 'joinObserved']))
    require(b'<!DOCTYPE' not in xml_bytes and b'<!ENTITY' not in xml_bytes)
    document = ET.fromstring(xml_bytes)
    require(document.tag == 'testsuite' and document.attrib == dict(name='capture-research', tests=str(len(definitions)), failures='0', errors='0', skipped='0'))
    cases = document.findall('testcase')
    require(len(cases) == len(definitions) and len(document) == len(definitions) + 1)
    properties = document.find('properties')
    require(properties is not None and len(properties) == 3)
    require(all(item.tag == 'property' and set(item.attrib) == {'name', 'value'} for item in properties))
    require({item.get('name'): item.get('value') for item in properties} == dict(sourceCommit=source, sourceDirty='false', api=str(api)))
    for case, entry, definition in zip(cases, runtime['methods'], definitions):
        require(case.attrib == dict(classname=CLASS, name=definition[0], time='0') and len(case) == 1)
        values = case.find('properties'); require(values is not None)
        expected = dict(actualStarted='1', actualCompleted='1', **entry['invocation']['observation'])
        require(len(values) == len(expected) and all(item.tag == 'property' and set(item.attrib) == {'name', 'value'} for item in values))
        require({item.get('name'): item.get('value') for item in values} == expected)
    return len(definitions)


def read_file(path, cap, started):
    try:
        require(path.is_absolute())
        for current in [path, *path.parents]:
            require(not current.is_symlink())
            require(not getattr(current, 'is_junction', lambda: False)())
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        try:
            info = os.fstat(descriptor)
            require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= cap and started - 2 <= info.st_mtime <= time.time() + 10)
            data = os.read(descriptor, cap + 1)
            require(len(data) == info.st_size)
            after = os.fstat(descriptor)
            current = path.lstat()
            require((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns))
            require((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino) and stat.S_ISREG(current.st_mode))
            return data
        finally:
            os.close(descriptor)
    except (OSError, ValueError):
        raise InvalidCapture('capture_report_unavailable') from None


def main():
    class SafeArguments(argparse.ArgumentParser):
        def error(self, message):
            print('Capture research verification failed.')
            raise SystemExit(2)
    parser = SafeArguments(description='Verify finite sanitized real-TUN research evidence')
    parser.add_argument('--source', required=True); parser.add_argument('--api', required=True, type=int, choices=[26, 37]); parser.add_argument('--started', required=True, type=int)
    options = parser.parse_args()
    try:
        require(re.fullmatch('[0-9a-f]{40}', options.source) is not None and 0 < options.started <= time.time() + 60)
        base = Path(__file__).resolve().parent.parent / 'build/reports/capture-runtime'
        runtime = load_json(read_file(base / 'runtime.json', 131072, options.started))
        host = load_json(read_file(base / 'host-cleanup.json', 16384, options.started))
        xml = read_file(base / 'TEST-capture-research.xml', 65536, options.started)
        count = verify(runtime, host, xml, options.source, options.api)
        print(f'Capture research verified: API {options.api}, {count} actual methods, owned cleanup complete.')
        return 0
    except (InvalidCapture, ValueError, TypeError, KeyError, ET.ParseError, OverflowError, RecursionError):
        print('Capture research verification failed.')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
