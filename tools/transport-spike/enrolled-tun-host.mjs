import { enrolledTunAcknowledgment, enrolledTunPayload } from './enrolled-tun-descriptor.mjs';
import { enrollmentPackage, enrollmentShellQuote, enrollmentPassed } from './enrollment-runtime-host.mjs';
import { enrollmentCommandObservation, enrollmentRuntimeValidation as V } from './enrollment-runtime-results.mjs';
import { parseEnrollmentJson } from '../../scripts/enrollment-corpus.mjs';

const address = enrolledTunPayload.address, cidr = address + '/' + enrolledTunPayload.prefix;
const refuse = code => { throw Error(code); };
export const enrolledTunAliasRefusals = Object.freeze(['unsupported_platform', 'alias_probe_failed', 'alias_preexisting',
  'alias_create_failed', 'alias_verify_failed', 'alias_cleanup_blocked', 'alias_remove_failed', 'alias_absence_unverified']);

function addresses(result) {
  if (!enrollmentPassed(result) || result.stderrBytes !== 0 || typeof result.output !== 'string' || Buffer.byteLength(result.output) > 65536) throw Error();
  const value = parseEnrollmentJson(Buffer.from(result.output));
  if (!Array.isArray(value) || value.length !== 1 || value[0]?.ifname !== 'lo' || !Array.isArray(value[0].addr_info) || value[0].addr_info.length > 64) throw Error();
  return value[0].addr_info.map(item => {
    if (!item || typeof item !== 'object' || item.family !== 'inet' || typeof item.local !== 'string' ||
        !Number.isInteger(item.prefixlen) || item.prefixlen < 0 || item.prefixlen > 32) throw Error();
    const bytes = item.local.split('.');
    if (bytes.length !== 4 || bytes.some(byte => !/^(?:0|[1-9][0-9]{0,2})$/.test(byte) || Number(byte) > 255)) throw Error();
    return { address: item.local, prefix: item.prefixlen };
  }).filter(item => item.address === address);
}

/** Only this fixed Linux alias is owned. A successful add retains ownership even if verification fails. */
export function createEnrolledTunAliasOwner(command, { platform = process.platform } = {}) {
  let owned = false, removing;
  const state = { platform: platform === 'linux' ? 'linux' : 'unsupported', initiallyAbsent: false, created: false,
    verified: false, removalRequested: false, removed: false, absenceConfirmed: false, refusal: null,
    commands: { before: null, create: null, verify: null, remove: null, after: null } };
  const snapshot = () => JSON.parse(JSON.stringify(state));
  const fail = reason => { state.refusal ??= reason; refuse('enrollment_fixture_failed'); };
  const run = async (key, args, cleanup = false) => {
    const result = await command('timeout', ['--kill-after=1s', '5s', ...args], 8000, {}, cleanup);
    state.commands[key] = enrollmentCommandObservation(result); return result;
  };
  const inspect = (key, cleanup = false) => run(key, ['ip', '-j', '-4', 'address', 'show', 'dev', 'lo'], cleanup);
  return Object.freeze({ snapshot,
    async prepare() {
      if (state.platform !== 'linux') fail('unsupported_platform');
      let before;
      try { before = addresses(await inspect('before')); } catch { fail('alias_probe_failed'); }
      if (before.length) fail('alias_preexisting');
      state.initiallyAbsent = true;
      let created;
      try { created = await run('create', ['sudo', '-n', 'ip', '-4', 'address', 'add', cidr, 'dev', 'lo']); }
      catch { fail('alias_create_failed'); }
      if (!enrollmentPassed(created)) fail('alias_create_failed');
      state.created = true; owned = true;
      let observed;
      try { observed = addresses(await inspect('verify')); } catch { fail('alias_verify_failed'); }
      if (observed.length !== 1 || observed[0].prefix !== enrolledTunPayload.prefix) fail('alias_verify_failed');
      state.verified = true; return snapshot();
    },
    async remove({ fixtureJoined }) {
      if (!state.created || state.removed && state.absenceConfirmed) return snapshot();
      if (removing) return removing;
      if (fixtureJoined !== true) fail('alias_cleanup_blocked');
      removing = (async () => {
        state.removalRequested = true;
        if (owned) {
          try {
            const result = await run('remove', ['sudo', '-n', 'ip', '-4', 'address', 'del', cidr, 'dev', 'lo'], true);
            if (enrollmentPassed(result)) owned = false;
          } catch { state.refusal ??= 'alias_remove_failed'; }
        }
        try { state.absenceConfirmed = addresses(await inspect('after', true)).length === 0; }
        catch { state.refusal ??= 'alias_absence_unverified'; }
        if (state.absenceConfirmed) owned = false;
        state.removed = V.commandPassed(state.commands.remove) && state.absenceConfirmed;
        if (!state.removed) fail(V.commandPassed(state.commands.remove) ? 'alias_absence_unverified' : 'alias_remove_failed');
        return snapshot();
      })();
      try { return await removing; } finally { removing = undefined; }
    },
  });
}

// Android8 toybox cp.c supplies mv -n. Keep the pending inode private through
// completed write/close/chmod, then same-directory rename without an old-gate overwrite.
export const enrolledTunGateScript = `set -eu
umask 077
directory=no_backup/draft-enrollment-research
temporary="$directory/.tun-complete-v1.pending"
destination="$directory/tun-complete-v1.bin"
created=false
cleanup() {
  status=$?
  trap - EXIT
  if [ "$created" = true ]; then
    if rm -f "$temporary"; then :; elif [ "$status" -eq 0 ]; then status=1; fi
  fi
  exit "$status"
}
trap cleanup EXIT
test -d "$directory"
test ! -L "$directory"
test ! -e "$temporary"
test ! -L "$temporary"
test ! -e "$destination"
test ! -L "$destination"
set -C
exec 3>"$temporary"
created=true
cat >&3
exec 3>&-
chmod 600 "$temporary"
test ! -e "$destination"
test ! -L "$destination"
mv -n "$temporary" "$destination"
test ! -e "$temporary"
test ! -L "$temporary"
created=false
echo TUN_GATE_PUBLISHED
`;

export async function publishEnrolledTunAcknowledgment(host) {
  const bytes = Buffer.from(enrolledTunAcknowledgment.bytes, 'ascii');
  let result;
  try {
    result = await host.adb(['shell', '-T', 'run-as', enrollmentPackage, 'sh', '-c', enrollmentShellQuote(enrolledTunGateScript)], 10000, { stdinBytes: bytes });
    return { byteCount: bytes.length, inputBytes: result.inputBytes ?? 0, inputFinished: result.inputFinished === true,
      inputClosed: result.inputClosed === true, command: enrollmentCommandObservation(result),
      published: enrollmentPassed(result) && result.stderrBytes === 0 && result.output.trim() === 'TUN_GATE_PUBLISHED' &&
        result.inputBytes === bytes.length && result.inputFinished === true && result.inputClosed === true };
  } finally { bytes.fill(0); }
}
