// Test peer only. Ephemeral keys live in the test's temporary directory.
import fs from 'node:fs';
import https from 'node:https';
import path from 'node:path';
import { WebSocketServer } from 'ws';

const directory = process.argv[2];
const server = https.createServer({
  key: fs.readFileSync(path.join(directory, 'server-key.pem')),
  cert: fs.readFileSync(path.join(directory, 'server.pem')),
  ca: fs.readFileSync(path.join(directory, 'client-ca.pem')),
  requestCert: true,
  rejectUnauthorized: true,
  minVersion: 'TLSv1.2',
}, (_request, response) => {
  response.writeHead(404).end();
});
const sockets = new WebSocketServer({ noServer: true, maxPayload: 65536, perMessageDeflate: false });
server.on('upgrade', (request, socket, head) => {
  if (!request.socket.authorized || request.url !== '/spike') {
    socket.destroy();
    return;
  }
  sockets.handleUpgrade(request, socket, head, websocket => {
    websocket.on('error', () => {});
    websocket.on('message', (bytes, isBinary) => {
      if (!isBinary) return websocket.close(1003, 'binary_required');
      websocket.send(bytes, { binary: true });
    });
  });
});
// Port zero prevents conflicts; communicate only the selected loopback port.
server.listen(0, '127.0.0.1', () => process.stdout.write(`${server.address().port}\n`));
