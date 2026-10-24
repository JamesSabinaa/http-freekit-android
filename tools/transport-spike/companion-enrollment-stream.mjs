// Research-only composition. No listener or operator interface is added to production.
import { X509Certificate } from 'node:crypto';
import { inspect } from 'node:util';
import { startEnrollmentHttpsFixture } from './companion-enrollment-https.mjs';
import { createCompanionStreamServer } from './companion-stream-peer.mjs';
import { EnrollmentFixtureError } from './companion-enrollment-https-assets.mjs';
import { enrollmentPublicSnapshot } from './companion-enrollment-crypto.mjs';

class EnrollmentStreamFixture {
  #enrollment; #stream;
  constructor(enrollment) { this.#enrollment = enrollment; this.#stream = enrollment.authenticatedService(); Object.freeze(this); }
  metadata() { return enrollmentPublicSnapshot({ ...this.#enrollment.metadata().material(), webSocketPort: this.#stream.port }); }
  createInvitation() { return this.#enrollment.createInvitation(); }
  waitForRegistered(id, options) { return this.#enrollment.waitForRegistered(id, options); }
  approve(id) { return this.#enrollment.approve(id); }
  reject(id) { return this.#enrollment.reject(id); }
  revoke(id) { return this.#enrollment.revoke(id); }
  readResult(id) { return this.#enrollment.readResult(id); }
  dropNextApprovedStatus() { return this.#enrollment.dropNextApprovedStatus(); }
  inspectEnrollment(id) { return this.#stream.inspectEnrollment(id); }
  snapshot() { return { ...this.#enrollment.snapshot(), stream: this.#stream.snapshot() }; }
  async close() { await this.#enrollment.close(); return this.snapshot(); }
  toJSON() { return this.snapshot(); }
  [inspect.custom]() { return '[Enrolled stream research fixture]'; }
}

export async function startEnrollmentStreamFixture({ directory, mode, openssl = process.env.OPENSSL_BIN ?? 'openssl',
  setupPort = 0, credentialPort = 0, streamPort = 0, credentialLifetimeSeconds = 60, sessionLifetimeMillis = 120000 } = {}) {
  if (!Number.isInteger(streamPort) || streamPort < 0 || streamPort > 65535 ||
      (streamPort && [setupPort, credentialPort].includes(streamPort)) ||
      !Number.isInteger(sessionLifetimeMillis) || sessionLifetimeMillis < 1000 || sessionLifetimeMillis > 1800000) throw new EnrollmentFixtureError();
  const enrollment = await startEnrollmentHttpsFixture({ directory, mode, openssl, setupPort, credentialPort, credentialLifetimeSeconds,
    authenticatedServiceFactory: async ({ tls, metadata, authorizeCertificate }) => createCompanionStreamServer({
      tls, authorize: socket => socket.authorized, desktopId: metadata.desktopId, logicalName: metadata.logicalName,
      port: streamPort, sessionLifetimeMillis,
      credentialAuthority: { authorizeCertificate, gatewayExpiresAt: new X509Certificate(Buffer.from(metadata.gatewayCertificateDer, 'base64url')).validTo },
    }),
  });
  return new EnrollmentStreamFixture(enrollment);
}
