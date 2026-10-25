import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { inspect } from 'node:util';
import { decodeStream, encodeStream } from './companion-protocol-codec.mjs';
import { encodeHttpOriginPreface, HttpOriginAcknowledgement, httpOriginAcknowledgementBytes } from './companion-http-origin.mjs';
import { loadHttpOriginVectors } from './companion-http-origin-vectors.mjs';
const vectors = loadHttpOriginVectors();

test('all fourteen grammar-authored raw-address producer vectors match exact canonical wire bytes', () => {
  assert.equal(vectors.requests.length,14);
  for (const entry of vectors.requests) {
    let actual;
    try { actual={outcome:'accepted',wireHex:encodeHttpOriginPreface(Buffer.from(entry.addressHex,'hex'),entry.port).toString('hex')}; }
    catch { actual={outcome:'rejected'}; }
    assert.deepEqual(actual,entry.expect,entry.id);
  }
});

test('all fourteen shared stream-codec vectors bind the actual optional-mode codec without inferred support', () => {
  assert.equal(vectors.opens.length,14);
  for (const entry of vectors.opens) {
    let actual;
    try { actual={outcome:'accepted',canonicalHex:encodeStream(decodeStream(Buffer.from(entry.wireHex,'hex'))).toString('hex')}; }
    catch(error) { actual={outcome:'rejected',code:error.code}; }
    assert.deepEqual(actual,entry.expect,entry.id);
  }
});

test('ten fixed200 consumer vectors finalize all input and preserve every coalesced and subsequent byte', () => {
  assert.equal(vectors.responses.length,10);
  for (const entry of vectors.responses) {
    let actual;
    try {
      const ack=new HttpOriginAcknowledgement(),remaining=[];
      for(const encoded of entry.chunksHex) { const chunk=Buffer.from(encoded,'hex'),count=ack.accept(chunk);remaining.push(chunk.subarray(count)); }
      actual=ack.complete?{outcome:'accepted',remainingHex:Buffer.concat(remaining).toString('hex')}:{outcome:'rejected'};
    } catch { actual={outcome:'rejected'}; }
    assert.deepEqual(actual,entry.expect,entry.id);
  }
});

test('producer material is copied and acknowledgement mismatch is terminal without retaining body/provider material', () => {
  const input=Buffer.from([203,0,113,10]),produced=encodeHttpOriginPreface(input);input.fill(0);
  assert.ok(produced.toString().includes('203.0.113.10:80'));produced.fill(0);assert.notEqual(encodeHttpOriginPreface(Buffer.from([203,0,113,10]))[0],0);
  const returned=httpOriginAcknowledgementBytes();returned.fill(0);assert.equal(httpOriginAcknowledgementBytes()[0],72);
  const ack=new HttpOriginAcknowledgement();assert.throws(()=>ack.accept(Buffer.from('CANARY_private')));
  assert.throws(()=>ack.accept(httpOriginAcknowledgementBytes()));assert.equal(ack.complete,false);
  for(const text of [String(ack),JSON.stringify(ack),inspect(ack)])assert.equal(text.includes('CANARY'),false);
  for(const source of [null,[1,2,3,4],new Uint8Array(65537)])assert.throws(()=>encodeHttpOriginPreface(source));
  const poisoned=new Proxy(new Uint8Array(4),{get(){throw Error('CANARY_provider');}});
  for(const operation of [()=>encodeHttpOriginPreface(poisoned),()=>new HttpOriginAcknowledgement().accept(poisoned)])assert.throws(operation,error=>error.code==='invalid_message'&&!String(error).includes('CANARY'));
  const bad=new HttpOriginAcknowledgement();assert.throws(()=>bad.accept(Buffer.alloc(1),1,1));assert.throws(()=>bad.accept(Buffer.alloc(0)));
});

test('shared vector file has bounded nonzero coverage, stable digest and frozen expectations', () => {
  assert.equal(vectors.sha256,'0419f01daa637ddc9433e2ee8f23cac86b841e2cf162a545ed9750e3077f463d');
  assert.equal(vectors.prefaces.length,23);assert.equal(Object.isFrozen(vectors.requests[0].expect),true);
  assert.throws(()=>{vectors.requests[0].expect.wireHex='';});
});

test('bounded vector loading rejects duplicates, unknown data, empty groups, unsafe hex and overflow without echoing it', () => {
  const directory=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'freekit-http-vectors-')));
  try {
    const filename=path.join(directory,'wire.json'),original=JSON.parse(fs.readFileSync(new URL('../../protocol/fixtures/c2-draft-0.5/wire.json',import.meta.url),'utf8'));
    for(const mutate of [value=>{value.requests=[];},value=>{value.opens[0].CANARY='private';},value=>{value.responses[0].chunksHex=['zz'];},
      value=>{value.prefaces[0].expect.family=true;},value=>{value.requests[1].id=value.requests[0].id;},value=>{value.requests[0].port=Number.MAX_SAFE_INTEGER;}]){
      const value=structuredClone(original);mutate(value);fs.writeFileSync(filename,JSON.stringify(value));
      assert.throws(()=>loadHttpOriginVectors(filename),error=>error.message==='invalid_http_origin_vectors'&&!String(error).includes('CANARY'));
    }
    for(const source of ['{"format":1,"format":2}',Buffer.alloc(131073,32),'{"x":NaN}']){fs.writeFileSync(filename,source);assert.throws(()=>loadHttpOriginVectors(filename));}
  } finally { assert.equal(path.dirname(directory),fs.realpathSync(os.tmpdir()));assert.ok(path.basename(directory).startsWith('freekit-http-vectors-'));fs.rmSync(directory,{recursive:true,force:true}); }
});
