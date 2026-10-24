// Isolated fixture mapping ownership. The supplied adb function throws on any command failure.
export function reserveFixtureReversePorts(adb, metadata, owned) {
  const names = ['enrollmentPort', 'webSocketPort'];
  const ports = names.map(name => metadata[name]);
  if (ports.some(port => !Number.isInteger(port) || port < 1 || port > 65535) || new Set(ports).size !== 2) {
    throw Error('invalid_distinct_fixture_ports');
  }
  const selected = {};
  for (let index = 0; index < names.length; index++) {
    const port = String(ports[index]);
    const response = adb(['reverse', '--no-rebind', `tcp:${port}`, `tcp:${port}`]);
    // A zero exit status means registration succeeded, even if its response is unexpected.
    // Keep that successful requested port owned so the caller's finally block can remove it.
    owned.push({ devicePort: port, hostPort: port });
    if (typeof response !== 'string' || (response.trim() !== '' && response.trim() !== port)) {
      throw Error('unexpected_reverse_registration_response');
    }
    selected[names[index]] = port;
  }
  return selected;
}

export function releaseOwnedReversePorts(adb, owned) {
  const failures = [];
  for (const mapping of owned.splice(0).reverse()) {
    try { adb(['reverse', '--remove', `tcp:${mapping.devicePort}`]); }
    catch { failures.push('owned_reverse_mapping_cleanup_failed'); }
  }
  return failures;
}
