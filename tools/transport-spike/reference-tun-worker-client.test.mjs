import test from 'node:test';
import assert from 'node:assert/strict';
import { inspect } from 'node:util';
import { startReferenceTunWorker, referenceTunStartupJoined } from './reference-tun-worker-client.mjs';
import { createCryptoFixture } from './companion-enrollment-crypto-fixtures.mjs';
import { enrollmentRequest } from './companion-enrollment-stream-client.mjs';
const plain = v => assert.equal(Object.getPrototypeOf(v),Object.prototype);
function joined(v) {
  for (const k of ['closeObserved','processGroupJoined','stdoutJoined','stderrJoined','stdinJoined']) assert.equal(v[k],true,k);
  assert.equal(v.pendingWrites,0); assert.equal(v.pendingRequests,0); assert.equal(v.forced,false);
  assert.equal(v.failure,null); assert.equal(v.exitCode,0); assert.equal(v.signal,null);
}
test('pure startup aggregation preserves negative or missing child cleanup evidence independently of joined process/pumps', () => {
  // Internal fault vector only: no claim of an actual ENOSPC, child exit or filesystem removal.
  const state = { closeObserved:true, processGroupJoined:true, stdinJoined:true, stdoutJoined:true,
    stderrJoined:true, pendingWrites:0, pendingRequests:0, forced:false };
  assert.equal(referenceTunStartupJoined(false,state),false);
  assert.equal(referenceTunStartupJoined(null,state),false);
  assert.equal(referenceTunStartupJoined(undefined,state),false);
  assert.equal(referenceTunStartupJoined(true,state),true);
  for (const key of ['closeObserved','processGroupJoined','stdinJoined','stdoutJoined','stderrJoined']) {
    assert.equal(referenceTunStartupJoined(true,{...state,[key]:false}),false,key);
  }
  assert.equal(referenceTunStartupJoined(true,{...state,forced:true}),false);
  assert.equal(referenceTunStartupJoined(true,{...state,pendingWrites:1}),false);
  assert.equal(referenceTunStartupJoined(true,{...state,pendingRequests:1}),false);
});
test('parent returns plain material after actual HTTPS registration and approval, then joins child/group/pumps', {timeout:35000}, async () => {
  const owner=await startReferenceTunWorker();
  try {
    const metadata=await owner.metadata(), invitation=await owner.createInvitation(); plain(metadata); plain(invitation);
    assert.equal(metadata.material,undefined); assert.equal(invitation.material,undefined);
    const original=metadata.desktopId; metadata.desktopId='mutated'; assert((await owner.metadata()).desktopId === original,'Defensive parent metadata');
    assert(!inspect(owner).includes(original)); assert(!JSON.stringify(owner).includes(original));
    const facade={metadata:()=>({material:()=>({...metadata,desktopId:original})})};
    const wait=owner.waitForRegistered(invitation.invitationId); const crypto=createCryptoFixture();
    const response=await enrollmentRequest(facade,'/companion/v1/pair',{protocolVersion:1,type:'pair',desktopId:original,
      invitationId:invitation.invitationId,invitationSecret:invitation.invitationSecret,csrDer:crypto.csr().toString('base64url'),
      deviceName:'Reference parent host test',capabilities:['tcp-http-origin-connect','tcp-https-connect']});
    assert.equal(response.status,200); const registered=await wait; plain(registered);
    assert(registered.enrollmentId === response.material.enrollmentId,'Actual registered identity agrees');
    const approved=await owner.approve(registered.enrollmentId); plain(approved); assert.equal(approved.type,'pair_approved');
    assert(JSON.stringify(await owner.readResult(registered.enrollmentId)) === JSON.stringify(approved),'Saved actual approval agrees');
    assert.equal((await owner.snapshot()).stream,null);
    assert.equal((await owner.inspectEnrollment(registered.enrollmentId)).probe,null);
  } finally { assert.equal((await owner.close()).privateDirectoryRemoved,true); joined(owner.processSnapshot()); }
});
test('parent reserves close with two pending real waits; admission seals synchronously', {timeout:35000}, async () => {
  const owner=await startReferenceTunWorker();
  const invitation=await owner.createInvitation();
  const a=assert.rejects(owner.waitForRegistered(invitation.invitationId),e=>['tun_enrollment','tun_closing'].includes(e.code));
  const b=assert.rejects(owner.waitForRegistered(invitation.invitationId),e=>['tun_enrollment','tun_closing'].includes(e.code));
  await assert.rejects(owner.snapshot(),e=>e.code==='tun_input');
  const close=owner.close(); await assert.rejects(owner.metadata(),e=>e.code==='tun_closing');
  assert.equal((await close).privateDirectoryRemoved,true); await Promise.all([a,b]); joined(owner.processSnapshot());
  assert.deepEqual(await owner.close(),await close);
});
test('parent reserves request128 for close after127 business requests', {timeout:35000}, async () => {
  const owner=await startReferenceTunWorker();
  try { for(let i=0;i<127;i++) await owner.snapshot(); await assert.rejects(owner.snapshot(),e=>e.code==='tun_input'); }
  finally { assert.equal((await owner.close()).privateDirectoryRemoved,true); joined(owner.processSnapshot()); }
});
test('parent validates hostile configuration without spawning or leaking it', async () => {
  for(const openssl of ['',null,'private\nsecret',{}]) await assert.rejects(startReferenceTunWorker({openssl}),e=>e.code==='tun_configuration' && !e.message.includes('secret'));
});
test('parent actual unavailable OpenSSL fails finite and joins startup cleanup', {timeout:35000}, async () => {
  await assert.rejects(startReferenceTunWorker({openssl:'/not-present/private-openssl'}),e=>e.code==='tun_unavailable' && !e.message.includes('private-openssl'));
});
