import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import { startOriginGatewayFixture } from './gateway-origin-fixture.mjs';
import { C3_DESKTOP_COMMIT } from './gateway-origin-desktop.mjs';

test('TUN origin preflight rejects an absent, broad or non-loopback alias before fixture startup', async t => {
  const platform = Object.getOwnPropertyDescriptor(process, 'platform');
  assert.equal(platform.configurable, true);
  Object.defineProperty(process, 'platform', { ...platform, value: 'linux' });
  let interfaces = {}, startups = 0;
  const marker = Error('preflight reached startup');
  t.mock.method(os, 'networkInterfaces', () => interfaces);
  t.mock.method(fs, 'mkdtempSync', () => { startups++; throw marker; });
  const options = { desktopRoot: process.cwd(), desktopCommit: C3_DESKTOP_COMMIT, profile: 'tun-http-h1', family: 'ipv4' };
  const alias = { family: 'IPv4', internal: true, address: '198.18.0.2', cidr: '198.18.0.2/32' };
  try {
    for (const value of [
      {}, { lo: [] }, { eth0: [alias] },
      ...[{ internal: false }, { family: 'IPv6' }, { address: '127.0.0.2' }, { cidr: '198.18.0.2/24' }]
        .map(change => ({ lo: [{ ...alias, ...change }] })),
    ]) {
      interfaces = value;
      await assert.rejects(startOriginGatewayFixture(options), error => error.code === 'origin_fixture_failed');
      assert.equal(startups, 0);
    }
    interfaces = { lo: [alias] };
    await assert.rejects(startOriginGatewayFixture({ ...options, family: 'ipv6' }), error => error.code === 'origin_fixture_failed');
    assert.equal(startups, 0);
    // This is a preflight unit check; the probe prevents all issuer, listener and network setup.
    await assert.rejects(startOriginGatewayFixture(options), error => error === marker);
    assert.equal(startups, 1);
  } finally { Object.defineProperty(process, 'platform', platform); }
});

test('TUN origin profile refuses an unsupported host instead of remapping its destination', async t => {
  const platform = Object.getOwnPropertyDescriptor(process, 'platform');
  Object.defineProperty(process, 'platform', { ...platform, value: 'win32' });
  let inspected = false;
  t.mock.method(os, 'networkInterfaces', () => { inspected = true; throw Error('unexpected interface inspection'); });
  try {
    await assert.rejects(startOriginGatewayFixture({ desktopRoot: process.cwd(), desktopCommit: C3_DESKTOP_COMMIT,
      profile: 'tun-http-h1', family: 'ipv4' }), error => error.code === 'origin_fixture_failed');
    assert.equal(inspected, false);
  } finally { Object.defineProperty(process, 'platform', platform); }
});
