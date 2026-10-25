export const captureClass = 'com.httpfreekit.capturetest.CapturePolicyInteropTest';
export const captureCases = Object.freeze([
  ['selectedTcpUsesTunAndNonselectedUidBypasses', 'uid', 2, { SelectedUidStable: 'true', SelectedHttp: '1', SelectedOpaque: '1', BypassHttp: '1', BypassOpaque: '1', MissingAuthRejected: 'true', WrongAuthRejected: 'true' }],
  ['directTcpUdpDnsAndUdp443Policy', 'direct', 1, { DirectTcp: '1', Udp: '1', Dns: '1', Udp443PositiveControl: 'true', Udp443NoDelivery: 'true', Udp443DropObserved: 'true' }],
  ['selectedIpv6UsesTun', 'ipv6', 1, { OriginalIpv6Validated: 'true', InterceptedIpv6: '1' }],
  ['stopJoinsCaptureAndAllowsFreshStart', 'stop', 2, { HeldRequestObserved: 'true', HeldRequestInterrupted: 'true', FreshStartForwards: 'true' }],
  ['protectAndBindFailuresFailClosed', 'guards', 2, { ProtectRefused: 'true', BindRefused: 'true', NoFlowConnect: 'true', RefusedSocketsClosed: 'true', RouteRetainedUntilStop: 'true' }],
].map(([method, scenario, starts, facts]) => Object.freeze({ method, scenario, starts, facts: Object.freeze(facts) })));
const phases = new Set(['setup', 'platform-consent', 'tun-start', 'local-auth-refusal', 'selected-traffic', 'nonselected-traffic',
  'udp443-positive-control', 'direct-protocols', 'blocked-udp443', 'selected-ipv6', 'held-intercepted-request', 'fresh-restart-traffic',
  'protect-refusal', 'bind-refusal', 'final-cleanup', 'actual-stop-join']);
const safeTypes = new Set(['AssertionError', 'IllegalArgumentException', 'IOException', 'IllegalStateException']);
const problems = new Set(['instrumentation_incomplete', 'instrumentation_failed', 'instrumentation_structure', 'instrumentation_bound',
  'invalid_capture_facts', 'host_setup_failed', 'device_unavailable', 'apk_build_failed', 'apk_install_failed', 'package_already_present',
  'clock_outside_bound', 'source_unavailable', 'fixture_setup_failed', 'cleanup_incomplete', 'research_cancelled']);
export const captureProblem = value => problems.has(value) ? value : 'host_setup_failed';
const fixedFailure = (line, scenario) => {
  const failure = /^java\.lang\.AssertionError: Capture research ([a-z]+) failed at ([a-z-]+) \(([A-Za-z]+)\); cleanup=(true|false)\.$/.exec(line);
  return failure && failure[1] === scenario && phases.has(failure[2]) && safeTypes.has(failure[3])
    ? { phase: failure[2], type: failure[3], cleanupCompleted: failure[4] === 'true' } : null;
};

export function captureFactExpectations(method, consentDialogObserved = 'false') {
  const item = captureCases.find(value => value.method === method);
  if (!item) throw Error('invalid_capture_method');
  return Object.freeze({ captureVersion: '1', captureScenario: item.scenario, captureStarts: String(item.starts), captureStops: String(item.starts),
    captureConsentGranted: 'true', captureConsentDialogObserved: consentDialogObserved, captureTunAndNativeObserved: 'true',
    captureAllStopsJoined: 'true', captureTrafficWorkerJoined: 'true', captureNotificationObserved: 'true',
    ...Object.fromEntries(Object.entries(item.facts).map(([key, value]) => [`capture${key}`, value])) });
}

/** One actual standalone JUnit invocation. Output is private; only fixed facts/categories survive. */
export function parseCaptureInvocation(bytes, method, command) {
  const definition = captureCases.find(value => value.method === method);
  if (!definition) throw Error('invalid_capture_method');
  const result = { method, state: 'incomplete', actualStarted: 0, actualCompleted: 0, terminalCount: 0, terminalCode: null,
    observation: null, failure: null, command: { exitCode: command?.code ?? null, signal: command?.signal ?? null,
      closeObserved: command?.closeObserved === true, processGroupClosed: command?.processGroupClosed === true, reason: command?.reason ? 'owned_command_failed' : null }, problems: [] };
  const fail = code => { if (!result.problems.includes(code)) result.problems.push(code); };
  let text;
  try {
    const input = typeof bytes === 'string' ? Buffer.from(bytes) : Buffer.from(bytes ?? []);
    if (input.length > 262144) throw Error();
    text = new TextDecoder('utf-8', { fatal: true }).decode(input);
  } catch { fail('instrumentation_bound'); return result; }
  let bundle = {}, active = false, completed = false, identity = false;
  for (const line of text.split(/\r?\n/)) {
    if (Buffer.byteLength(line) > 8192) { fail('instrumentation_bound'); continue; }
    const status = /^INSTRUMENTATION_STATUS: ([A-Za-z][A-Za-z0-9_]*)=(.*)$/.exec(line);
    if (status) {
      if (result.terminalCount) fail('instrumentation_structure');
      if (Object.hasOwn(bundle, status[1]) || Object.keys(bundle).length >= 32) fail('instrumentation_structure');
      else bundle[status[1]] = status[2];
      if (status[1] === 'stack') result.failure = fixedFailure(status[2], definition.scenario);
      continue;
    }
    const statusCode = /^INSTRUMENTATION_STATUS_CODE: (-?[0-9]+)$/.exec(line);
    if (statusCode) {
      const code = Number(statusCode[1]);
      if (result.terminalCount) fail('instrumentation_structure');
      if (code === 1) {
        result.actualStarted++;
        identity = bundle.class === captureClass && bundle.test === method;
        if (active || completed || !identity || Object.keys(bundle).some(key => key.startsWith('capture'))) fail('instrumentation_structure');
        active = true;
      } else if (code === 2) {
        const expected = captureFactExpectations(method, bundle.captureConsentDialogObserved);
        if (!active || completed || result.observation || !['true', 'false'].includes(bundle.captureConsentDialogObserved) ||
            Object.keys(bundle).length !== Object.keys(expected).length || Object.entries(expected).some(([key, value]) => bundle[key] !== value)) fail('invalid_capture_facts');
        else result.observation = { ...bundle };
      } else {
        result.actualCompleted++;
        if (!active || completed || bundle.class !== captureClass || bundle.test !== method || code !== 0) fail(code === 0 ? 'instrumentation_structure' : 'instrumentation_failed');
        active = false; completed = true;
      }
      bundle = {};
      continue;
    }
    const terminal = /^INSTRUMENTATION_CODE: (-?[0-9]+)$/.exec(line);
    if (terminal) { if (!completed || active || Object.keys(bundle).length) fail('instrumentation_structure'); result.terminalCount++; result.terminalCode = Number(terminal[1]); }
    result.failure ??= fixedFailure(line, definition.scenario);
    if (/^(?:INSTRUMENTATION_FAILED|INSTRUMENTATION_ABORTED|INSTRUMENTATION_RESULT: shortMsg=)/.test(line)) fail('instrumentation_failed');
  }
  if (Object.keys(bundle).length || active || !identity || !completed || result.actualStarted !== 1 || result.actualCompleted !== 1 ||
      result.terminalCount !== 1 || result.terminalCode !== -1 || !result.observation) fail('instrumentation_incomplete');
  if (result.command.exitCode !== 0 || result.command.signal !== null || !result.command.closeObserved || !result.command.processGroupClosed || result.command.reason) fail('instrumentation_failed');
  result.state = result.problems.length ? result.actualCompleted ? 'failed' : 'incomplete' : 'passed';
  return result;
}

export function captureReceiverGate(index, before, after) {
  const delta = name => after[name] - before[name];
  if (![before, after].every(value => value && value.closed === false && Object.keys(value).sort().join(',') === SNAPSHOT_KEYS && Object.values(value).every(item => typeof item === 'boolean' || Number.isSafeInteger(item) && item >= 0 && item <= 10000000))) return false;
  if (delta('invalidRequests') !== 0) return false;
  if (index === 0) return ['interceptedHttp', 'interceptedOpaque', 'directHttp', 'directOpaque'].every(name => delta(name) === 1);
  if (index === 1) return delta('directTcp') === 1 && delta('udp') === 1 && delta('dns') === 1 && delta('udp443') === 1;
  if (index === 2) return delta('interceptedIpv6') === 1 && delta('directHttp') === 0;
  if (index === 3) return delta('heldRequestsClosed') === 1 && delta('interceptedHttp') === 1 && after.heldConnections === 0;
  return index === 4 && ['directTcp', 'interceptedHttp', 'interceptedOpaque', 'udp'].every(name => delta(name) === 0);
}

const SNAPSHOT_KEYS = ['directHttp', 'directOpaque', 'directTcp', 'udp', 'dns', 'udp443', 'interceptedHttp', 'interceptedOpaque', 'interceptedIpv6',
  'uploadBytes', 'downloadBytes', 'invalidRequests', 'heldRequestsClosed', 'activeSockets', 'pendingCallbacks', 'timers', 'listeners', 'heldConnections', 'closed'].sort().join(',');
export function captureReportAccepted(report) {
  if (!report || report.format !== 'http-freekit-capture-runtime' || report.revision !== 1 ||
      !/^[0-9a-f]{40}$/.test(report.source?.commit ?? '') || report.source.trackedDirty !== false || ![26, 37].includes(report.api) || report.problems?.length !== 0) return false;
  const clock = report.clock;
  if (!clock || !Object.values(clock).every(Number.isSafeInteger) || clock.hostAfterMillis < clock.hostBeforeMillis ||
      clock.roundTripMillis !== clock.hostAfterMillis - clock.hostBeforeMillis || clock.roundTripMillis > 2000 ||
      clock.lowerBoundMillis !== clock.deviceEpochSeconds * 1000 - clock.hostAfterMillis ||
      clock.upperBoundMillis !== clock.deviceEpochSeconds * 1000 + 999 - clock.hostBeforeMillis || clock.lowerBoundMillis < -2000 || clock.upperBoundMillis > 2000) return false;
  if (!Array.isArray(report.methods) || report.methods.length !== 5) return false;
  for (const [index, item] of report.methods.entries()) {
    const invocation = item?.invocation, definition = captureCases[index];
    if (!invocation || invocation.method !== definition.method || invocation.state !== 'passed' || invocation.actualStarted !== 1 || invocation.actualCompleted !== 1 ||
        invocation.terminalCount !== 1 || invocation.terminalCode !== -1 || invocation.problems?.length !== 0 ||
        invocation.command?.exitCode !== 0 || invocation.command.signal !== null || invocation.command.reason !== null ||
        invocation.command.closeObserved !== true || invocation.command.processGroupClosed !== true || !invocation.observation) return false;
    const expected = captureFactExpectations(definition.method, invocation.observation.captureConsentDialogObserved);
    if (!['true', 'false'].includes(invocation.observation.captureConsentDialogObserved) || index === 0 && invocation.observation.captureConsentDialogObserved !== 'true' ||
        Object.keys(expected).length !== Object.keys(invocation.observation).length || Object.entries(expected).some(([key, value]) => invocation.observation[key] !== value) ||
        !captureReceiverGate(index, item.receiversBefore, item.receiversAfter)) return false;
  }
  const cleanup = report.cleanup;
  return cleanup?.ownedCommandsClosed === true && cleanup.ownedCommandGroupsClosed === true && cleanup.packagesAbsent === true &&
    ['forceStopExitCodes', 'uninstallExitCodes'].every(name => Array.isArray(cleanup[name]) && cleanup[name].length === 4 && cleanup[name].every(code => code === 0)) &&
    cleanup.receivers?.closed === true && ['activeSockets', 'pendingCallbacks', 'timers', 'listeners', 'heldConnections'].every(name => cleanup.receivers[name] === 0);
}

const xml = value => String(value).replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[character]);
export function captureXml(report) {
  const failed = report.methods.filter(item => item.invocation.state !== 'passed').length;
  return `<?xml version="1.0" encoding="UTF-8"?>\n<testsuite name="capture-research" tests="5" failures="${failed}" errors="${report.accepted ? 0 : 1}" skipped="0">\n` +
    `<properties><property name="sourceCommit" value="${xml(report.source.commit)}"/><property name="sourceDirty" value="${report.source.trackedDirty}"/><property name="api" value="${report.api}"/></properties>\n` +
    report.methods.map(item => `<testcase classname="${captureClass}" name="${item.invocation.method}" time="0">` +
      `<properties><property name="actualStarted" value="${item.invocation.actualStarted}"/><property name="actualCompleted" value="${item.invocation.actualCompleted}"/>` +
      Object.entries(item.invocation.observation ?? {}).map(([name, value]) => `<property name="${xml(name)}" value="${xml(value)}"/>`).join('') + '</properties>' +
      (item.invocation.state === 'passed' ? '' : `<failure type="research_incomplete">${xml(item.invocation.problems.join(','))}</failure>`) + '</testcase>').join('\n') +
    '\n</testsuite>\n';
}
