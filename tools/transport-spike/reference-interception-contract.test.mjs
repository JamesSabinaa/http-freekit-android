import test from 'node:test';
import assert from 'node:assert/strict';
import { inspect } from 'node:util';
import { createHash } from 'node:crypto';
import { referenceInterceptionProfile as profile, referenceInterceptionResponse, ReferenceInterceptionError } from './reference-interception-contract.mjs';

test('reference interception profile is fixed and does not add a wire mode', () => {
  assert.ok(Object.isFrozen(profile));
  assert.deepEqual(profile, { address: '198.18.0.2', hostname: 'reference-target.invalid', path: '/reference/proof',
    httpPort: 80, httpsPort: 443, maxBodyBytes: 4096, maxHeaderBytes: 4096, maxOwners: 2, timeoutMillis: 5000 });
  assert.throws(() => { profile.address = '127.0.0.1'; }, TypeError);
});

test('actual origin response binds bounded bytes and returns independent buffers', () => {
  const body = Buffer.from('synthetic private body');
  const expected = Buffer.from('reference-origin:' + createHash('sha256').update(body).digest('hex'));
  const first = referenceInterceptionResponse(body);
  assert.deepEqual(first, expected);
  first.fill(0);
  assert.deepEqual(referenceInterceptionResponse(body), expected);
  assert.notDeepEqual(referenceInterceptionResponse(Buffer.from('different')), expected);
  assert.equal(referenceInterceptionResponse(Buffer.alloc(4096)).length, 81);
  for (const bad of [null, 'body', {}, Buffer.alloc(4097)]) assert.throws(() => referenceInterceptionResponse(bad), ReferenceInterceptionError);
});

test('finite errors never serialize supplied provider or path details or invent a join', () => {
  const error = new ReferenceInterceptionError('/private/provider/SECRET', 'true');
  assert.deepEqual(error.toJSON(), { code: 'backend_failed', joined: false });
  for (const text of [String(error), JSON.stringify(error), inspect(error)]) assert.doesNotMatch(text, /SECRET|private|provider/);
  assert.deepEqual(new ReferenceInterceptionError('cleanup_unjoined', false).toJSON(), { code: 'cleanup_unjoined', joined: false });
});
