'use strict'

// The escape suite.
//
// Each posture runs ONE container that emits `key=value` lines, then we assert on the report.
// One container per assertion would be correct but glacial; one report per posture keeps the
// whole suite inside a few seconds while still being a real end-to-end test.
//
// Read the negative-control test at the bottom first. It is the reason to trust the rest.

const test = require('brittle')
const os = require('bare-os')
const env = require('bare-env')
const h = require('./harness.js')

const HOST_UID = typeof os.getuid === 'function' ? os.getuid() : 1000
const HOST_USER = env.USER || 'ryan'
const HOST_HOME = env.HOME || '/home/' + HOST_USER

// Emits a flat report. Every probe is wrapped so a failure never aborts the script -- a missing
// line would silently pass an `absent` assertion, so we always print something.
const PROBE = `
set +e
say () { echo "$1=$2"; }

say uid "$(id -u)"
say capeff "$(grep '^CapEff' /proc/self/status | awk '{print $2}')"
say capbnd "$(grep '^CapBnd' /proc/self/status | awk '{print $2}')"

# Is the host uid mapped into this namespace at all?
say uidmap "$(tr -s ' ' ',' < /proc/self/uid_map | tr '\\n' ';')"

# --- host filesystem -----------------------------------------------------------------
say canary_abs "$(cat ${HOST_HOME}/${h.CANARY_NAME} 2>/dev/null | head -1)"
say canary_mount "$(cat /host/${h.CANARY_NAME} 2>/dev/null | head -1)"
say canary_proc1 "$(cat /proc/1/root${HOST_HOME}/${h.CANARY_NAME} 2>/dev/null | head -1)"
say host_home "$(test -d ${HOST_HOME} && echo present || echo absent)"
say host_user_in_home "$(ls /home 2>/dev/null | grep -x '${HOST_USER}' || echo none)"
say ssh_key "$(cat ${HOST_HOME}/.ssh/id_ed25519 2>/dev/null | head -1 | cut -c1-20)"
say npmrc "$(cat ${HOST_HOME}/.npmrc 2>/dev/null | head -1 | cut -c1-20)"

# --- sockets and devices -------------------------------------------------------------
say podman_sock "$(test -S /run/user/${HOST_UID}/podman/podman.sock && echo present || echo absent)"
say any_socket "$(find / -xdev -type s 2>/dev/null | head -3 | tr '\\n' ',')"
say dev_kvm "$(test -e /dev/kvm && echo present || echo absent)"
say dev_list "$(ls /dev 2>/dev/null | tr '\\n' ',')"

# --- filesystem posture --------------------------------------------------------------
say rootfs_write "$(touch /escape-probe 2>/dev/null && echo WRITABLE || echo readonly)"
say tmp_write "$(touch /tmp/probe 2>/dev/null && echo ok || echo failed)"

# --- network -------------------------------------------------------------------------
say ifaces "$(ls /sys/class/net 2>/dev/null | tr '\\n' ',')"
# NB: iproute2 is NOT in ubuntu:24.04 -- \`ip route\` returns nothing because the binary is
# missing, which made an earlier version of this probe vacuously pass in BOTH postures. The
# negative control caught it. /proc/net/route is kernel-provided and always present; a
# destination of 00000000 is the default route.
say default_route "$(awk 'NR>1 && $2==\"00000000\" {n++} END {print n+0}' /proc/net/route 2>/dev/null)"
say route_lines "$(awk 'NR>1 {n++} END {print n+0}' /proc/net/route 2>/dev/null)"
say resolve "$(getent hosts registry.npmjs.org 2>/dev/null | head -1 | awk '{print $1}')"

# --- syscall surface -----------------------------------------------------------------
say unshare "$(unshare -Ur true 2>&1 >/dev/null | head -1; echo "rc=$?")"
say unshare_caps "$(unshare -Ur sh -c 'grep ^CapEff /proc/self/status | awk "{print \\$2}"' 2>/dev/null || echo blocked)"
say mount_try "$(mkdir -p /tmp/m 2>/dev/null; mount -t tmpfs none /tmp/m 2>&1 | head -1 || echo ok)"

# --- limits --------------------------------------------------------------------------
say pids_max "$(cat /sys/fs/cgroup/pids.max 2>/dev/null || echo unknown)"
say nproc_lim "$(ulimit -u)"
echo REPORT_END
`

function parse(stdout) {
  const out = {}
  for (const line of stdout.split('\n')) {
    const i = line.indexOf('=')
    if (i > 0) out[line.slice(0, i).trim()] = line.slice(i + 1).trim()
  }
  return out
}

let ENVP = null
const reports = {}

async function reportFor(key, run) {
  if (reports[key]) return reports[key]
  const res = await run()
  reports[key] = { res, r: parse(res.stdout) }
  return reports[key]
}

test('escape suite: environment', async (t) => {
  h.plantCanary()
  ENVP = await h.probeEnvironment()
  if (!ENVP.ok) {
    t.comment('skipping whole suite: ' + ENVP.why)
    t.pass('skipped')
    return
  }
  t.pass('podman + image available; microvm=' + ENVP.microvm)
})

// =======================================================================================
// HARDENED -- host-safety assertions. These apply to BOTH tiers, because they are about the
// host, not about the guest's internal privilege model.
// =======================================================================================

for (const tier of ['container', 'microvm']) {
  test(`hardened/${tier}: no host filesystem access`, async (t) => {
    if (!ENVP || !ENVP.ok) return t.pass('skipped')
    if (tier === 'microvm' && !ENVP.microvm) {
      t.comment('microvm unavailable')
      return t.pass('skipped')
    }

    const { res, r } = await reportFor(tier, () => h.runHardened(tier, ENVP.digest, PROBE))
    t.is(res.code, 0, 'probe ran\n' + res.stderr.slice(0, 400))

    // The single most important assertion in the file: the canary must not appear ANYWHERE in
    // the output, by any route. Checking the whole stream (not just the canary lines) catches a
    // leak we did not think to probe for directly.
    t.absent(res.stdout.includes(h.CANARY_TEXT), 'canary text absent from the entire probe output')
    t.is(r.canary_abs, '', 'canary unreadable by absolute host path')
    t.is(r.canary_mount, '', 'canary unreadable via a mount')
    t.is(r.canary_proc1, '', 'canary unreadable via /proc/1/root')
    t.is(r.host_user_in_home, 'none', `no /home/${HOST_USER}`)
    t.is(r.ssh_key, '', 'host ssh key unreadable')
    t.is(r.npmrc, '', 'host npmrc (npm token) unreadable')
  })

  test(`hardened/${tier}: no sockets, no host devices`, async (t) => {
    if (!ENVP || !ENVP.ok) return t.pass('skipped')
    if (tier === 'microvm' && !ENVP.microvm) return t.pass('skipped')
    const { r } = await reportFor(tier, () => h.runHardened(tier, ENVP.digest, PROBE))

    // Mounting this is instant root-equivalent on the host, and it exists on this machine.
    t.is(r.podman_sock, 'absent', 'podman socket not reachable')
    t.is(r.any_socket, '', 'no unix sockets anywhere in the sandbox')
    // /dev/kvm is granted to the host-side VMM, never to the workload.
    t.is(r.dev_kvm, 'absent', 'kvm not exposed to the workload')
  })

  test(`hardened/${tier}: no network`, async (t) => {
    if (!ENVP || !ENVP.ok) return t.pass('skipped')
    if (tier === 'microvm' && !ENVP.microvm) return t.pass('skipped')
    const { r } = await reportFor(tier, () => h.runHardened(tier, ENVP.digest, PROBE))

    // No default route is the assertion that matters -- it is the absence of any egress path.
    t.is(r.default_route, '0', 'no default route')
    if (tier === 'container') {
      t.is(r.route_lines, '0', 'routing table is entirely empty')
    } else {
      // krun synthesises a dummy0 in the guest with a single route to 203.0.113.0/24 (TEST-NET-3,
      // the documentation range) and no gateway. It is deliberately unroutable, so its presence is
      // expected; what must hold is that it provides no way out.
      t.is(r.route_lines, '1', 'only the krun dummy route')
      t.is(r.default_route, '0', 'and it is not a default route')
    }
    // Guards against the probe silently becoming vacuous again: awk must have produced a number.
    t.ok(
      /^\d+$/.test(r.default_route),
      'route probe actually ran (got ' + JSON.stringify(r.default_route) + ')'
    )
    t.is(r.resolve, '', 'cannot resolve a hostname')
    const ifaces = r.ifaces.split(',').filter(Boolean)
    // krun synthesises a dummy0 in the guest; what matters is that nothing routes anywhere.
    t.absent(
      ifaces.some((i) => /^(eth|en|wl|tap|veth)/.test(i)),
      'no routable interface: ' + r.ifaces
    )
  })

  test(`hardened/${tier}: rootfs immutable, workspace writable`, async (t) => {
    if (!ENVP || !ENVP.ok) return t.pass('skipped')
    if (tier === 'microvm' && !ENVP.microvm) return t.pass('skipped')
    const { r } = await reportFor(tier, () => h.runHardened(tier, ENVP.digest, PROBE))
    t.is(r.rootfs_write, 'readonly', '--read-only holds')
    t.is(r.tmp_write, 'ok', '/tmp is usable, or every real build breaks')
  })
}

// =======================================================================================
// HARDENED -- container tier ONLY. These are assertions about the guest's internal privilege
// model, which is the boundary for the container tier and NOT the boundary for microvm.
//
// Measured under krun: uid 0, CapEff 000001ffffffffff, nested unshare succeeds. That is correct
// and expected -- the VM is the boundary there. Asserting these under microvm would be a wrong
// test, so the suite does not.
// =======================================================================================

test('hardened/container: capabilities are empty', async (t) => {
  if (!ENVP || !ENVP.ok) return t.pass('skipped')
  const { r } = await reportFor('container', () => h.runHardened('container', ENVP.digest, PROBE))
  t.is(r.uid, '1000', 'not container-root')
  t.is(r.capeff, '0000000000000000', 'no effective capabilities')
  t.is(
    r.capbnd,
    '0000000000000000',
    'empty bounding set -- this is what blocks nested-userns escalation'
  )
})

test('hardened/container: host uid is not mapped in', async (t) => {
  if (!ENVP || !ENVP.ok) return t.pass('skipped')
  const { r } = await reportFor('container', () => h.runHardened('container', ENVP.digest, PROBE))
  // --userns=auto deliberately omits the host uid, so even container-root owns nothing outside.
  t.absent(
    r.uidmap.includes(`,${HOST_UID},`),
    `host uid ${HOST_UID} absent from uid_map: ${r.uidmap}`
  )
})

test('hardened/container: namespace + mount syscalls denied', async (t) => {
  if (!ENVP || !ENVP.ok) return t.pass('skipped')
  const { r } = await reportFor('container', () => h.runHardened('container', ENVP.digest, PROBE))
  t.ok(/not permitted|failed/i.test(r.unshare), 'unshare refused: ' + r.unshare)
  t.absent(r.unshare_caps.includes('ffffffffff'), 'no full-cap nested namespace: ' + r.unshare_caps)
  t.ok(/denied|permitted|must be superuser/i.test(r.mount_try), 'mount refused: ' + r.mount_try)
})

test('hardened/container: pid limit is in force', async (t) => {
  if (!ENVP || !ENVP.ok) return t.pass('skipped')
  const { r } = await reportFor('container', () => h.runHardened('container', ENVP.digest, PROBE))
  t.is(r.pids_max, '512', 'cgroup pids.max matches --pids-limit')
  t.is(r.nproc_lim, '512', 'rlimit nproc is a second, independent fork brake')
})

// =======================================================================================
// THE NEGATIVE CONTROL
//
// Run the identical probe against a deliberately weakened posture. If these assertions fail,
// the suite above is not measuring anything and must not be trusted.
// =======================================================================================

test('negative control: the weakened posture FAILS the host-safety probes', async (t) => {
  if (!ENVP || !ENVP.ok) return t.pass('skipped')

  const res = await h.runWeakened(ENVP.digest, PROBE)
  if (res.code !== 0 && !res.stdout.includes('REPORT_END')) {
    t.comment('weakened posture could not start: ' + res.stderr.trim().split('\n')[0])
    t.comment('(pasta/keep-id may be unavailable here; the control is inconclusive)')
    t.pass('inconclusive')
    return
  }
  const r = parse(res.stdout)

  // Host FS leak, via the bind mount our builder refuses to emit.
  t.ok(res.stdout.includes(h.CANARY_TEXT), 'weakened posture LEAKS the canary -- probe is live')
  t.is(r.canary_mount, h.CANARY_TEXT, 'canary readable through the bind mount')

  // Privilege model wide open.
  t.not(r.capeff, '0000000000000000', 'weakened posture keeps capabilities: ' + r.capeff)
  t.ok(r.uidmap.includes(`,${HOST_UID},`), 'keep-id maps the host uid straight in: ' + r.uidmap)

  // Network reachable. This assertion is also what proves the hardened route probe is real
  // rather than vacuous -- an earlier version used `ip route`, which is not installed in this
  // image, so both postures reported 0 and the hardened test passed for the wrong reason.
  t.not(r.default_route, '0', 'weakened posture has a default route: ' + r.default_route)
  t.not(r.route_lines, '0', 'weakened posture has a routing table')

  // And with the default seccomp profile plus caps, nested userns escalation works -- the exact
  // thing our profile and --cap-drop are there to stop.
  t.absent(/not permitted/i.test(r.unshare), 'unshare succeeds unconfined: ' + r.unshare)
})

test('escape suite: teardown', (t) => {
  h.removeCanary()
  t.pass('canary removed')
})
