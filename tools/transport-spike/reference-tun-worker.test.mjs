import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { FORMAT, validateRequest } from './reference-tun-worker.mjs';
import { bounded } from './companion-stream-peer-io.mjs';
const entry = fileURLToPath(new URL('./reference-tun-worker.mjs',import.meta.url));
const wire = (id,op,args={}) => JSON.stringify({format:FORMAT,revision:1,id,op,args});
test('canonical requests enforce private tag, ordering, IDs, exact args and reserved close', () => {
  for (const op of ['metadata','createInvitation','snapshot','close']) assert.equal(validateRequest(wire(1,op),1).op,op);
  for (const op of ['approve','readResult','inspectEnrollment']) assert.equal(validateRequest(wire(1,op,{id:'enr_'+'A'.repeat(43)}),1).op,op);
  assert.equal(validateRequest(wire(1,'waitForRegistered',{id:'actual_invitation',timeoutMillis:10000}),1).args.timeoutMillis,10000);
  assert.equal(validateRequest(wire(128,'close'),128).op,'close');
  assert.throws(() => validateRequest(wire(128,'snapshot'),128),e => e.code === 'tun_input');
  assert.throws(() => validateRequest(wire(129,'close'),129),e => e.code === 'tun_input');
  const hostile = [wire(128,'metadata'),wire(129,'close'),wire(2,'snapshot'),wire(1,'enroll'),wire(1,'stop'),
    wire(1,'snapshot',{private:true}),wire(1,'waitForRegistered',{id:'x',timeoutMillis:10001}),
    wire(1,'waitForRegistered',{id:'x',timeoutMillis:0}),wire(1,'approve',{id:'../private'}),
    wire(1,'readResult',{id:'x',extra:1}),wire(1,'snapshot').replace(FORMAT,'http-freekit-reference-interception-peer'),
    ' '+wire(1,'snapshot'),wire(1,'snapshot').replace('"revision":1','"revision":1,"revision":1'),
    JSON.stringify({revision:1,format:FORMAT,id:1,op:'snapshot',args:{}}),'null','[]','{}'];
  for (const line of hostile) assert.throws(() => validateRequest(line,1),e => e.code === 'tun_input');
});
async function cli({args=[],input='',end=true}={}) {
  // Suppress only the known experimental category, never TLS/security warnings.
  const child = spawn(process.execPath,['--disable-warning=ExperimentalWarning',entry,...args],{stdio:['pipe','pipe','pipe']});
  const out=[],err=[]; let size=0;
  child.stdout.on('data',b => { size+=b.length; if (size>32768) child.kill('SIGKILL'); else out.push(b); });
  child.stderr.on('data',b => err.push(b)); child.stdin.on('error',()=>{});
  const closed = new Promise(resolve => child.once('close',(code,signal)=>resolve({code,signal})));
  child.stdin.write(input); if(end) child.stdin.end();
  try { return {...await bounded(closed,30000),out:Buffer.concat(out).toString(),err:Buffer.concat(err).toString()}; }
  finally { if(child.exitCode===null && child.signalCode===null) { child.kill('SIGKILL'); await closed; } }
}
test('child CLI rejects extra arguments without printing arguments or material', {timeout:35000}, async () => {
  const result=await cli({args:['private-do-not-print']});
  assert.equal(result.code,1); assert.equal(result.signal,null);
  const v=JSON.parse(result.out.trim()); assert.equal(v.code,'tun_configuration'); assert.equal(v.joined,true);
  assert(!result.out.includes('private-do-not-print')); assert.equal(result.err,'');
});
for (const [label,input] of [['malformed','{bad}\n'],['duplicate',wire(1,'snapshot').replace('"id":1','"id":1,"id":1')+'\n'],
  ['oversize','x'.repeat(8193)+'\n'],['control','\u0000\n'],['nonascii','é\n'],['EOF','']]) {
  test(`child CLI ${label} seals and cleans without material disclosure`,{timeout:35000},async () => {
    const result=await cli({input}); assert.equal(result.code,1); assert.equal(result.signal,null);
    const rows=result.out.trim().split('\n').map(line=>JSON.parse(line));
    const last=rows.at(-1); assert.equal(last.event,'failed'); assert.equal(last.code,'tun_input');
    assert.equal(last.format,FORMAT); assert.equal(typeof last.joined,'boolean');
    assert(!result.out.includes('invitationSecret')); assert(!result.out.includes('BEGIN'));
  });
}
