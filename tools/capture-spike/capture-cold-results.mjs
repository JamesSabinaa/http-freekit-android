export const captureColdClass = 'com.httpfreekit.capturetest.CaptureColdTcpInteropTest';
export const captureColdMethod = 'coldUnboundHttpRequiresStrictEof';

const cumulative = Object.freeze(['directHttp', 'directOpaque', 'directTcp', 'udp', 'dns', 'udp443',
  'interceptedHttp', 'interceptedOpaque', 'interceptedIpv6', 'uploadBytes', 'downloadBytes', 'invalidRequests',
  'heldRequestsClosed', 'heldCloseRequests', 'tcpConnections', 'udpDatagrams', 'deadlineCloseRequests', 'tcpErrorEvents', 'tcpResetErrors']);
const resources = Object.freeze(['activeSockets', 'pendingCallbacks', 'timers', 'listeners', 'heldConnections']);
export const captureColdSnapshotKeys = Object.freeze([...cumulative, ...resources, 'closed'].sort());
export const captureColdCleanupKeys = Object.freeze(['forceStopExitCodes', 'uninstallExitCodes', 'packagesAbsent',
  'ownedCommandsClosed', 'ownedCommandGroupsClosed', 'receivers'].sort());
const reportProblems = new Set(['source_unavailable', 'device_unavailable', 'clock_outside_bound', 'apk_build_failed',
  'package_already_present', 'apk_install_failed', 'host_setup_failed', 'fixture_setup_failed', 'research_cancelled', 'cleanup_incomplete']);
const parseProblems = new Set(['instrumentation_bound', 'instrumentation_structure', 'invalid_cold_facts',
  'instrumentation_failed', 'instrumentation_incomplete']);
export const captureColdProblem = value => reportProblems.has(value) ? value : 'host_setup_failed';

const observationKeys = Object.freeze(['coldVersion', 'coldScenario', 'coldOwnerAbsentBefore', 'coldOwnerAbsentAfter',
  'coldRouteObserved', 'coldHttpAttempts', 'coldTrafficCommand', 'coldTrafficStatus', 'coldTrafficBytes',
  'coldTrafficSha256', 'coldFailurePhase', 'coldFailureCode', 'coldCleanupJoined']);
const phases = new Set(['none', 'setup', 'route', 'http', 'client-cleanup', 'owner-check']);
const failureCodes = new Set(['none', 'cold_setup', 'cold_route_reply', 'cold_tcp_reply', 'cold_client_cleanup', 'cold_owner_present',
  'traffic_route_unavailable', 'traffic_command_failed', 'traffic_close_io']);
for (const stage of ['connect', 'write', 'shutdown', 'reply', 'eof', 'close'])
  for (const category of ['timeout', 'io', 'protocol', 'other', 'reset', 'aborted', 'closed', 'bad_fd', 'not_connected'])
    failureCodes.add(`traffic_tcp_${stage}_${category}`);
for (const present of [0, 1]) for (const internet of [0, 1]) for (const vpn of [0, 1])
  failureCodes.add(`traffic_route_nonvpn_timeout_p${present}_i${internet}_v${vpn}`);
const replyHash = '05dfd86ee3ecc0267ceb6234e1955c1e8c80e34b6323b2b1c87c7d1d84042255';
const fullMatch = (value, pattern) => typeof value === 'string' && pattern.exec(value)?.[0] === value;
const shape = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));

function observation(value, code) {
  if (!shape(value, observationKeys) || observationKeys.some(key => typeof value[key] !== 'string') ||
      value.coldVersion !== '1' || value.coldScenario !== 'cold-http' ||
      ['coldOwnerAbsentBefore', 'coldOwnerAbsentAfter', 'coldRouteObserved', 'coldCleanupJoined'].some(key => !['true', 'false'].includes(value[key])) ||
      !['0', '1'].includes(value.coldHttpAttempts) || !['0', '18', '10'].includes(value.coldTrafficCommand) ||
      !['-1', '0', '1', '2', '3'].includes(value.coldTrafficStatus) ||
      !fullMatch(value.coldTrafficBytes, /^(?:0|[1-9][0-9]{0,4})$/) || Number(value.coldTrafficBytes) > 65507 ||
      value.coldTrafficSha256 !== 'none' && !fullMatch(value.coldTrafficSha256, /^[a-f0-9]{64}$/) ||
      !phases.has(value.coldFailurePhase) || !failureCodes.has(value.coldFailureCode)) return null;
  if (code === 2) {
    if (['coldOwnerAbsentBefore', 'coldOwnerAbsentAfter', 'coldRouteObserved', 'coldCleanupJoined'].some(key => value[key] !== 'true') ||
        value.coldHttpAttempts !== '1' || value.coldTrafficCommand !== '10' || value.coldTrafficStatus !== '0' ||
        value.coldTrafficBytes !== '32787' || value.coldTrafficSha256 !== replyHash ||
        value.coldFailurePhase !== 'none' || value.coldFailureCode !== 'none') return null;
  } else if (code !== 3 || value.coldFailurePhase === 'none' || value.coldFailureCode === 'none') return null;
  // Negative facts intentionally have no extra sequencing constraints: preserve the first failure.
  return Object.freeze(Object.fromEntries(observationKeys.map(key => [key, value[key]])));
}

const signals = new Set(['SIGINT', 'SIGTERM', 'SIGKILL', 'SIGHUP', 'SIGABRT', 'SIGSEGV', 'SIGPIPE', 'SIGQUIT',
  'SIGILL', 'SIGBUS', 'SIGALRM', 'SIGUSR1', 'SIGUSR2', 'SIGTRAP', 'SIGFPE', 'SIGXCPU', 'SIGXFSZ', 'SIGSYS']);
function commandSnapshot(command) {
  const knownSignal = command?.signal === null || signals.has(command?.signal);
  return { exitCode: Number.isSafeInteger(command?.code) && Math.abs(command.code) <= 255 ? command.code : null,
    signal: signals.has(command?.signal) ? command.signal : null,
    closeObserved: command?.closeObserved === true, processGroupClosed: command?.processGroupClosed === true,
    reason: command?.reason != null || !knownSignal ? 'owned_command_failed' : null };
}

/** Parse only one real standalone invocation; provider output and stack text never become report material. */
export function parseCaptureColdInvocation(bytes, command) {
  const result = { method: captureColdMethod, state: 'incomplete', actualStarted: 0, actualCompleted: 0,
    terminalCount: 0, terminalCode: null, observation: null, failure: null, command: commandSnapshot(command), problems: [] };
  const fail = code => { if (!result.problems.includes(code)) result.problems.push(code); };
  let text;
  try {
    if (!(typeof bytes === 'string' || bytes instanceof Uint8Array) ||
        (typeof bytes === 'string' ? Buffer.byteLength(bytes) : bytes.byteLength) > 262144) throw Error();
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(typeof bytes === 'string' ? Buffer.from(bytes) : bytes);
  } catch { fail('instrumentation_bound'); return result; }
  let bundle = {}, active = false, completed = false, seenObservation = false;
  const metadata = new Set(['class', 'test', 'id', 'current', 'numtests', 'stack', 'stream']);
  for (const line of text.split(/\r?\n/)) {
    if (Buffer.byteLength(line) > 8192) { fail('instrumentation_bound'); continue; }
    const field = /^INSTRUMENTATION_STATUS: ([A-Za-z][A-Za-z0-9_]*)=(.*)$/.exec(line);
    if (field) {
      if (result.terminalCount || Object.hasOwn(bundle, field[1]) || Object.keys(bundle).length >= 48) fail('instrumentation_structure');
      else bundle[field[1]] = field[2];
      continue;
    }
    const status = /^INSTRUMENTATION_STATUS_CODE: (.*)$/.exec(line);
    if (status) {
      if (!fullMatch(status[1], /^(?:0|-?[1-9][0-9]{0,8})$/)) { fail('instrumentation_structure'); bundle = {}; continue; }
      const code = Number(status[1]);
      if (result.terminalCount) fail('instrumentation_structure');
      if (code === 1) {
        result.actualStarted++;
        if (active || completed || bundle.class !== captureColdClass || bundle.test !== captureColdMethod ||
            Object.keys(bundle).some(key => !metadata.has(key))) fail('instrumentation_structure');
        if (Object.hasOwn(bundle, 'stack')) fail('instrumentation_failed');
        active = true;
      } else if (code === 2 || code === 3) {
        const decoded = observation(bundle, code);
        if (!active || completed || seenObservation || !decoded) fail('invalid_cold_facts');
        if (decoded && !result.observation) result.observation = decoded;
        if (code === 3) {
          fail('instrumentation_failed');
          if (decoded && !result.failure) result.failure = Object.freeze({ phase: decoded.coldFailurePhase, code: decoded.coldFailureCode });
        }
        seenObservation = true;
      } else if ([-4, -3, -2, -1, 0].includes(code)) {
        result.actualCompleted++;
        if (!active || completed || bundle.class !== captureColdClass || bundle.test !== captureColdMethod ||
            Object.keys(bundle).some(key => !metadata.has(key))) fail('instrumentation_structure');
        if (code === 0 && Object.hasOwn(bundle, 'stack')) fail('instrumentation_failed');
        if (code !== 0) fail('instrumentation_failed');
        active = false; completed = true;
      } else fail('instrumentation_structure');
      bundle = {};
      continue;
    }
    const terminal = /^INSTRUMENTATION_CODE: (.*)$/.exec(line);
    if (terminal) {
      if (!fullMatch(terminal[1], /^(?:0|-?[1-9][0-9]{0,8})$/) || !completed || active || Object.keys(bundle).length) fail('instrumentation_structure');
      result.terminalCount++;
      result.terminalCode = fullMatch(terminal[1], /^(?:0|-?[1-9][0-9]{0,8})$/) ? Number(terminal[1]) : null;
    }
    if (/^INSTRUMENTATION_(?:STATUS:|STATUS_CODE:|FAILED|ABORTED|RESULT: shortMsg=)/.test(line)) fail('instrumentation_failed');
  }
  if (Object.keys(bundle).length || active || !completed || result.actualStarted !== 1 || result.actualCompleted !== 1 ||
      result.terminalCount !== 1 || result.terminalCode !== -1 || !result.observation) fail('instrumentation_incomplete');
  if (result.command.exitCode !== 0 || result.command.signal !== null || result.command.reason !== null ||
      !result.command.closeObserved || !result.command.processGroupClosed) fail('instrumentation_failed');
  result.state = result.problems.length ? result.actualCompleted ? 'failed' : 'incomplete' : 'passed';
  return result;
}

function snapshot(value) {
  return shape(value, captureColdSnapshotKeys) && typeof value.closed === 'boolean' &&
    [...cumulative, ...resources].every(key => Number.isSafeInteger(value[key]) && value[key] >= 0 && value[key] <= 10000000) &&
    value.tcpResetErrors <= value.tcpErrorEvents;
}
const positiveVector = Object.freeze({ directHttp: 1, tcpConnections: 1, uploadBytes: 16528, downloadBytes: 32787 });
const clockKeys = ['deviceEpochSeconds', 'hostBeforeMillis', 'hostAfterMillis', 'roundTripMillis', 'lowerBoundMillis', 'upperBoundMillis'];
function clockValid(value) {
  return shape(value, clockKeys) && clockKeys.every(key => Number.isSafeInteger(value[key])) &&
    value.deviceEpochSeconds >= 946684800 && value.deviceEpochSeconds <= 4102444800 &&
    value.hostBeforeMillis >= 946684800000 && value.hostAfterMillis <= 4102444800000 && value.hostAfterMillis >= value.hostBeforeMillis &&
    value.roundTripMillis === value.hostAfterMillis - value.hostBeforeMillis && value.roundTripMillis <= 2000 &&
    value.lowerBoundMillis === value.deviceEpochSeconds * 1000 - value.hostAfterMillis &&
    value.upperBoundMillis === value.deviceEpochSeconds * 1000 + 999 - value.hostBeforeMillis &&
    value.lowerBoundMillis >= -2000 && value.upperBoundMillis <= 2000;
}
function invocationPassed(value) {
  return shape(value, ['method', 'state', 'actualStarted', 'actualCompleted', 'terminalCount', 'terminalCode', 'observation', 'failure', 'command', 'problems']) &&
    value.method === captureColdMethod && value.state === 'passed' && value.actualStarted === 1 && value.actualCompleted === 1 &&
    value.terminalCount === 1 && value.terminalCode === -1 && value.failure === null && Array.isArray(value.problems) && value.problems.length === 0 &&
    observation(value.observation, 2) !== null && shape(value.command, ['exitCode', 'signal', 'reason', 'closeObserved', 'processGroupClosed']) &&
    value.command.exitCode === 0 && value.command.signal === null && value.command.reason === null &&
    value.command.closeObserved === true && value.command.processGroupClosed === true;
}

/** Recompute the gate independently of the mutable report.accepted output field. */
export function captureColdReportAccepted(report) {
  try {
    if (!shape(report, ['format', 'revision', 'source', 'api', 'clock', 'method', 'cleanup', 'problems', 'accepted']) ||
        report.format !== 'http-freekit-capture-cold-tcp' || report.revision !== 1 || report.api !== 26 || typeof report.accepted !== 'boolean' ||
        !shape(report.source, ['commit', 'trackedDirty']) || !fullMatch(report.source.commit, /^[0-9a-f]{40}$/) || report.source.trackedDirty !== false ||
        !clockValid(report.clock) || !Array.isArray(report.problems) || report.problems.length !== 0 ||
        !shape(report.method, ['invocation', 'receiversBefore', 'receiversAfter']) || !invocationPassed(report.method.invocation)) return false;
    const before = report.method.receiversBefore, after = report.method.receiversAfter, cleanup = report.cleanup;
    if (!snapshot(before) || !snapshot(after) || before.closed || after.closed ||
        cumulative.some(key => before[key] !== 0 || after[key] !== (positiveVector[key] ?? 0)) ||
        resources.some(key => before[key] !== (key === 'listeners' ? 7 : 0) || after[key] !== (key === 'listeners' ? 7 : 0)) ||
        !shape(cleanup, captureColdCleanupKeys) || cleanup.packagesAbsent !== true || cleanup.ownedCommandsClosed !== true || cleanup.ownedCommandGroupsClosed !== true ||
        ['forceStopExitCodes', 'uninstallExitCodes'].some(key => !Array.isArray(cleanup[key]) || cleanup[key].length !== 3 || !cleanup[key].every(code => code === 0)) ||
        !snapshot(cleanup.receivers) || cleanup.receivers.closed !== true || resources.some(key => cleanup.receivers[key] !== 0) ||
        cumulative.some(key => cleanup.receivers[key] !== after[key])) return false;
    return true;
  } catch { return false; }
}

const xml = value => String(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[c]);
export function captureColdXml(report) {
  try {
    const invocation = report?.method?.invocation;
    const passed = invocationPassed(invocation);
    const accepted = report?.accepted === true && captureColdReportAccepted(report);
    const facts = observation(invocation?.observation, 2) ?? observation(invocation?.observation, 3);
    const count = key => Number.isSafeInteger(invocation?.[key]) && invocation[key] >= 0 && invocation[key] <= 1000000 ? invocation[key] : 0;
    const commit = fullMatch(report?.source?.commit, /^[0-9a-f]{40}$/) ? report.source.commit : 'unavailable';
    const dirty = report?.source?.trackedDirty === false ? false : true;
    const problems = Array.isArray(invocation?.problems) ? [...new Set(invocation.problems.map(code => parseProblems.has(code) ? code : 'instrumentation_structure'))] : ['instrumentation_incomplete'];
    const output = `<?xml version="1.0" encoding="UTF-8"?>\n<testsuite name="capture-cold-tcp" tests="1" failures="${passed ? 0 : 1}" errors="${accepted ? 0 : 1}" skipped="0">\n` +
      `<properties><property name="sourceCommit" value="${commit}"/><property name="sourceDirty" value="${dirty}"/><property name="api" value="${report?.api === 26 ? 26 : 0}"/></properties>\n` +
      `<testcase classname="${captureColdClass}" name="${captureColdMethod}" time="0"><properties>` +
      `<property name="actualStarted" value="${count('actualStarted')}"/><property name="actualCompleted" value="${count('actualCompleted')}"/>` +
      (facts ? observationKeys.map(key => `<property name="${key}" value="${xml(facts[key])}"/>`).join('') : '') + '</properties>' +
      (passed ? '' : `<failure type="research_incomplete">${xml(problems.join(','))}</failure>`) + '</testcase>\n</testsuite>\n';
    if (Buffer.byteLength(output) > 65536) throw Error();
    return output;
  } catch { throw Error('invalid_cold_report'); }
}
