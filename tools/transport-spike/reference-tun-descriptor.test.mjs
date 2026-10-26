import test from 'node:test';
import assert from 'node:assert/strict';
import * as D from './reference-tun-descriptor.mjs';
test('private descriptor admits exactly two ordered methods and distinct bounded gate', () => {
  assert.deepEqual(D.referenceTunMethods, ['selectedUidHttpReachesReferenceOriginThroughTun', 'selectedUidH1HttpsReachesReferenceOriginThroughTun']);
  assert.equal(D.referenceTunPhases.length, 16);
  assert.equal(new Set(D.referenceTunPhases).size, 16);
  assert.ok(D.referenceTunPhases.indexOf('local-stream-drained') < D.referenceTunPhases.indexOf('gateway-complete-acknowledged'));
  assert.ok(D.referenceTunPhases.indexOf('gateway-complete-acknowledged') < D.referenceTunPhases.indexOf('capture-stop-joined'));
  assert.equal(D.referenceTunAcknowledgment.bytes, 'FREEKIT-REFERENCE-TUN-COMPLETE-V1\n');
  assert.match(D.referenceTunAcknowledgment.path, /\/reference-tun-complete-v1\.bin$/);
  assert.equal(new Set(Object.values(D.referenceTunReportPaths)).size, 4);
  for (const value of Object.values(D.referenceTunReportPaths)) assert.ok(value.includes('reference-tun'));
});
test('observations and failures are finite, immutable and do not disclose private values', () => {
  assert.equal(D.referenceTunVersion, 1);
  assert.ok(Object.isFrozen(D.referenceTunObservationTypes));
  assert.ok(Object.isFrozen(D.referenceTunFailureCategories));
  assert.equal(D.referenceTunObservationTypes.Version, 'version');
  assert.equal(D.referenceTunObservationTypes.HostCompleteAcknowledged, 'true');
  assert.equal(D.referenceTunObservationTypes.SessionLease, 'false');
  for (const key of Object.keys(D.referenceTunObservationTypes)) assert.doesNotMatch(key, /Sha256|Secret|Der|Identity/);
  assert.equal(new Set(D.referenceTunFailureCategories).size, D.referenceTunFailureCategories.length);
  assert.ok(D.referenceTunFailureCategories.includes('traffic_reference_eof'));
});
