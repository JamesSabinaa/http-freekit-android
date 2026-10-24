// Owned test subprocess. TEMP input is deliberately never printed or exported.
import fs from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { openEnrollmentStore } from './companion-enrollment-store.mjs';

const input = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
let armed = false;
const halt = marker => { fs.writeSync(1, marker + '\n'); Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0); };
const exec = DatabaseSync.prototype.exec, authorizer = DatabaseSync.prototype.setAuthorizer;
DatabaseSync.prototype.setAuthorizer = function (callback) {
  // Force dirty-page spill for crash-before-COMMIT evidence, before installing the production authorizer.
  exec.call(this, 'PRAGMA cache_size=2'); return authorizer.call(this, callback);
};
DatabaseSync.prototype.exec = function (sql) {
  if (armed && input.position === 'before' && sql === 'COMMIT') halt('BEFORE_COMMIT');
  return exec.call(this, sql);
};
try {
  const store = openEnrollmentStore({ directory: input.directory, metadata: input.metadata,
    clock: () => ({ utcMillis: input.utcMillis, monotonicMillis: 0 }) });
  let job;
  if (input.operation === 'publish') job = store.beginApproval(input.enrollmentId).job;
  armed = true;
  if (input.operation === 'reserve') store.reserve(input.pair);
  else if (input.operation === 'claim') store.beginApproval(input.enrollmentId);
  else if (input.operation === 'publish') store.publish(job, Buffer.from(input.candidate, 'base64url'));
  else if (input.operation === 'revoke') store.revoke(input.enrollmentId);
  else throw Error();
  halt('AFTER_COMMIT');
} catch { fs.writeSync(1, 'FAILED\n'); process.exitCode = 1; }
