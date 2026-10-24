// Pure owned IPC-test child. No authority, files, issuer or listener exists here.
const mode = process.argv[2] ?? 'normal';
const closed = { admissionClosed: true, listenersClosed: true, storeClosed: true, issuerChildrenJoined: true,
  activeSockets: 0, pendingCallbacks: 0, pendingTimers: 0, issuerJobs: 0, signerGroups: 0, workers: 0 };
process.on('message', message => {
  if (message.op === 'close') {
    process.send({ revision: 1, id: message.id, ok: true, result: closed }, () => process.disconnect());
    return;
  }
  if (mode === 'hang') return;
  const response = { revision: 1, id: message.id, ok: true, result: { value: 'PRIVATE_IPC_MATERIAL' } };
  if (mode === 'malformed') response.extra = 'PRIVATE_PROTOCOL_CAUSE';
  process.send(response);
});
