"""Independent cold no-VPN TCP acceptance gate. Never prints provider messages or report payloads."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import time
import xml.etree.ElementTree as ET

CLASS = 'com.httpfreekit.capturetest.CaptureColdTcpInteropTest'
METHOD = 'coldUnboundHttpRequiresStrictEof'
CUMULATIVE = ['directHttp', 'directOpaque', 'directTcp', 'udp', 'dns', 'udp443', 'interceptedHttp',
              'interceptedOpaque', 'interceptedIpv6', 'uploadBytes', 'downloadBytes', 'invalidRequests',
              'heldRequestsClosed', 'heldCloseRequests', 'tcpConnections', 'udpDatagrams',
              'deadlineCloseRequests', 'tcpErrorEvents', 'tcpResetErrors']
OWNED = ['activeSockets', 'pendingCallbacks', 'timers', 'listeners', 'heldConnections']
SNAPSHOT = set(CUMULATIVE + OWNED + ['closed'])
FACTS = dict(coldVersion='1', coldScenario='cold-http', coldOwnerAbsentBefore='true', coldOwnerAbsentAfter='true',
             coldRouteObserved='true', coldHttpAttempts='1', coldTrafficCommand='10', coldTrafficStatus='0',
             coldTrafficBytes='32787', coldTrafficSha256='05dfd86ee3ecc0267ceb6234e1955c1e8c80e34b6323b2b1c87c7d1d84042255',
             coldFailurePhase='none', coldFailureCode='none', coldCleanupJoined='true')
POSITIVE = dict.fromkeys(CUMULATIVE, 0)
POSITIVE.update(directHttp=1, tcpConnections=1, uploadBytes=16528, downloadBytes=32787)


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


def snapshot(value, closed):
    exact(value, SNAPSHOT)
    require(value['closed'] is closed)
    for key in SNAPSHOT - {'closed'}:
        integer(value[key])
    require(value['tcpResetErrors'] <= value['tcpErrorEvents'])


def verify(runtime, host, xml_bytes, source, api=26):
    require(re.fullmatch('[0-9a-f]{40}', source) is not None and type(api) is int and api == 26)
    exact(runtime, ['format', 'revision', 'source', 'api', 'clock', 'method', 'cleanup', 'problems', 'accepted'])
    require(runtime['format'] == 'http-freekit-capture-cold-tcp' and runtime['accepted'] is True and runtime['problems'] == [])
    integer(runtime['revision'], 1, 1); integer(runtime['api'], 26, 26)
    exact(runtime['source'], ['commit', 'trackedDirty'])
    require(runtime['source']['commit'] == source and runtime['source']['trackedDirty'] is False)
    clock = runtime['clock']
    exact(clock, ['deviceEpochSeconds', 'hostBeforeMillis', 'hostAfterMillis', 'roundTripMillis', 'lowerBoundMillis', 'upperBoundMillis'])
    for key, value in clock.items():
        integer(value, -2000 if key.endswith('BoundMillis') else 0, 4_102_444_800_000)
    require(946_684_800 <= clock['deviceEpochSeconds'] <= 4_102_444_800 and 946_684_800_000 <= clock['hostBeforeMillis'] <= clock['hostAfterMillis'])
    require(clock['roundTripMillis'] == clock['hostAfterMillis'] - clock['hostBeforeMillis'] <= 2000)
    require(clock['lowerBoundMillis'] == clock['deviceEpochSeconds'] * 1000 - clock['hostAfterMillis'] >= -2000)
    require(clock['upperBoundMillis'] == clock['deviceEpochSeconds'] * 1000 + 999 - clock['hostBeforeMillis'] <= 2000)
    entry = runtime['method']
    exact(entry, ['invocation', 'receiversBefore', 'receiversAfter'])
    invocation = entry['invocation']
    exact(invocation, ['method', 'state', 'actualStarted', 'actualCompleted', 'terminalCount', 'terminalCode', 'observation', 'failure', 'command', 'problems'])
    require(invocation['method'] == METHOD and invocation['state'] == 'passed' and invocation['failure'] is None and invocation['problems'] == [])
    for key in ['actualStarted', 'actualCompleted', 'terminalCount']:
        integer(invocation[key], 1, 1)
    integer(invocation['terminalCode'], -1, -1)
    command = invocation['command']
    exact(command, ['exitCode', 'signal', 'closeObserved', 'processGroupClosed', 'reason'])
    integer(command['exitCode'], 0, 0)
    require(command['signal'] is None and command['reason'] is None and command['closeObserved'] is True and command['processGroupClosed'] is True)
    require(invocation['observation'] == FACTS)
    before, after = entry['receiversBefore'], entry['receiversAfter']
    snapshot(before, False); snapshot(after, False)
    require(all(before[key] == 0 and after[key] == POSITIVE[key] for key in CUMULATIVE))
    require(all(before[key] == after[key] == (7 if key == 'listeners' else 0) for key in OWNED))
    cleanup = runtime['cleanup']
    exact(cleanup, ['forceStopExitCodes', 'uninstallExitCodes', 'packagesAbsent', 'ownedCommandsClosed', 'ownedCommandGroupsClosed', 'receivers'])
    for key in ['packagesAbsent', 'ownedCommandsClosed', 'ownedCommandGroupsClosed']:
        require(cleanup[key] is True)
    for key in ['forceStopExitCodes', 'uninstallExitCodes']:
        require(type(cleanup[key]) is list and len(cleanup[key]) == 3)
        for code in cleanup[key]:
            integer(code, 0, 0)
    snapshot(cleanup['receivers'], True)
    require(all(cleanup['receivers'][key] == 0 for key in OWNED) and all(cleanup['receivers'][key] == after[key] for key in CUMULATIVE))
    exact(host, ['format', 'revision', 'sourceCommit', 'api', 'driverExitCode', 'emulatorStarted', 'stopAttempted', 'stopExitCode', 'terminationObserved', 'joinObserved', 'emulatorExitCode'])
    require(host['format'] == 'http-freekit-capture-cold-host-cleanup' and host['sourceCommit'] == source)
    integer(host['revision'], 1, 1); integer(host['api'], 26, 26)
    for key in ['driverExitCode', 'stopExitCode', 'emulatorExitCode']:
        integer(host[key], 0, 0)
    require(all(host[key] is True for key in ['emulatorStarted', 'stopAttempted', 'terminationObserved', 'joinObserved']))
    require(type(xml_bytes) is bytes and 0 < len(xml_bytes) <= 65536 and b'<!' not in xml_bytes)
    document = ET.fromstring(xml_bytes)
    require(document.tag == 'testsuite' and document.attrib == dict(name='capture-cold-tcp', tests='1', failures='0', errors='0', skipped='0'))
    require(len(document) == 2 and [item.tag for item in document] == ['properties', 'testcase'])
    properties, case = document
    require(len(properties) == 3 and all(item.tag == 'property' and set(item.attrib) == {'name', 'value'} and len(item) == 0 for item in properties))
    require({item.get('name'): item.get('value') for item in properties} == dict(sourceCommit=source, sourceDirty='false', api='26'))
    require(case.attrib == dict(classname=CLASS, name=METHOD, time='0') and len(case) == 1 and case[0].tag == 'properties')
    values = case[0]; expected = dict(actualStarted='1', actualCompleted='1', **FACTS)
    require(len(values) == len(expected) and all(item.tag == 'property' and set(item.attrib) == {'name', 'value'} and len(item) == 0 for item in values))
    require({item.get('name'): item.get('value') for item in values} == expected)
    require(all(item.text is None or not item.text.strip() for item in document.iter()) and all(item.tail is None or not item.tail.strip() for item in document.iter()))
    return 1


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
            print('Cold TCP comparison verification failed.')
            raise SystemExit(2)
    parser = SafeArguments(description='Verify finite isolated cold TCP evidence')
    parser.add_argument('--source', required=True); parser.add_argument('--api', required=True, type=int, choices=[26]); parser.add_argument('--started', required=True, type=int)
    options = parser.parse_args()
    try:
        require(re.fullmatch('[0-9a-f]{40}', options.source) is not None and 0 < options.started <= time.time() + 60)
        base = Path(__file__).resolve().parent.parent / 'build/reports/capture-cold-tcp'
        require({path.name for path in base.iterdir()} == {'runtime.json', 'host-cleanup.json', 'TEST-capture-cold-tcp.xml'})
        runtime = load_json(read_file(base / 'runtime.json', 131072, options.started))
        host = load_json(read_file(base / 'host-cleanup.json', 16384, options.started))
        xml = read_file(base / 'TEST-capture-cold-tcp.xml', 65536, options.started)
        verify(runtime, host, xml, options.source, options.api)
        print('Cold TCP comparison verified: API26, one actual method, owned cleanup complete.')
        return 0
    except (InvalidCapture, OSError, ValueError, TypeError, KeyError, ET.ParseError, OverflowError, RecursionError):
        print('Cold TCP comparison verification failed.')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
