'use strict'

// Interpolation and condition tests. Pure, table-driven.
//
// The negative table is the point. "An unknown reference is a hard error" is the single most
// user-visible decision in this file, and there is a dedicated group asserting that the things we
// deliberately did NOT build -- arithmetic, functions, GHA's `${{ }}` -- are rejected rather than
// silently half-working.

const test = require('brittle')
const { interpolate, evaluate, truthy, ROOTS, STATUS_FNS } = require('../lib/interpolate.js')

const SCOPE = {
  target: { name: 'linux-x64', platform: 'linux', arch: 'x64', host: false },
  matrix: { node: '22' },
  env: { APP: 'MyApp', EMPTY: '' },
  needs: { version: { outputs: { value: '1.2.3' }, status: 'success' } },
  steps: { build: { outputs: { sha: 'abc123' }, status: 'success' } },
  job: { name: 'make', id: 'make' },
  run: { id: 'r1', tier: 'microvm' }
}

test('interpolation resolves every root', (t) => {
  t.is(interpolate('{{ target }}', SCOPE), 'linux-x64', 'a bare target is its name')
  t.is(interpolate('{{ target.platform }}/{{ target.arch }}', SCOPE), 'linux/x64')
  t.is(interpolate('{{ matrix.node }}', SCOPE), '22')
  t.is(interpolate('{{ env.APP }}', SCOPE), 'MyApp')
  t.is(interpolate('{{ needs.version.outputs.value }}', SCOPE), '1.2.3')
  t.is(interpolate('{{ needs.version.status }}', SCOPE), 'success')
  t.is(interpolate('{{ steps.build.outputs.sha }}', SCOPE), 'abc123')
  t.is(interpolate('{{ job.name }}', SCOPE), 'make')
  t.is(interpolate('{{ run.id }}', SCOPE), 'r1')
})

test('interpolation handles surrounding text and repeats', (t) => {
  t.is(interpolate('app-{{ target }}-{{ env.APP }}.zip', SCOPE), 'app-linux-x64-MyApp.zip')
  t.is(interpolate('{{ target }}{{ target }}', SCOPE), 'linux-x64linux-x64')
  t.is(interpolate('no refs here', SCOPE), 'no refs here')
  t.is(interpolate('{{env.APP}}', SCOPE), 'MyApp', 'whitespace is optional')
  t.is(interpolate('{{   env.APP   }}', SCOPE), 'MyApp', 'and generous')
  t.is(interpolate('{{ env.EMPTY }}', SCOPE), '', 'an empty declared value is legitimately empty')
})

test('an unknown reference is a hard error, never an empty string', (t) => {
  // This is the headline behaviour. GHA silently substitutes '' and the build does the wrong thing
  // for the rest of its life.
  const bad = [
    ['{{ matrix.nodee }}', /unknown reference "matrix.nodee"/],
    ['{{ env.NOPE }}', /unknown reference "env.NOPE"/],
    ['{{ needs.missing.outputs.x }}', /unknown reference "needs.missing"/],
    ['{{ steps.absent.outputs.x }}', /unknown reference "steps.absent"/],
    ['{{ secrets.TOKEN }}', /unknown reference root "secrets"/],
    ['{{ github.sha }}', /unknown reference root "github"/],
    ['{{ target.nope }}', /unknown reference "target.nope"/]
  ]
  for (const [src, pattern] of bad) {
    try {
      interpolate(src, SCOPE)
      t.fail('should have thrown: ' + src)
    } catch (err) {
      t.ok(pattern.test(err.message), `${src} -> ${err.message}`)
    }
  }
})

test('the error names what IS available', (t) => {
  try {
    interpolate('{{ needs.version.outputs.nope }}', SCOPE)
    t.fail('should have thrown')
  } catch (err) {
    t.ok(/available: value/.test(err.message), 'lists the real keys: ' + err.message)
  }
})

test('referring to a group rather than a value is rejected', (t) => {
  t.exception(() => interpolate('{{ env }}', SCOPE), /refers to a group/)
  t.exception(() => interpolate('{{ needs.version.outputs }}', SCOPE), /refers to a group/)
})

test('malformed interpolation is rejected', (t) => {
  t.exception(() => interpolate('{{ unbalanced', SCOPE), /unbalanced/)
  t.exception(
    () => interpolate('{{ }}', SCOPE),
    /malformed reference/,
    'an empty reference is malformed, not an unknown root'
  )
  t.exception(() => interpolate('{{ a..b }}', SCOPE), /malformed reference/)
})

test('GHA syntax is not silently accepted', (t) => {
  // `${{ }}` would leave a stray `$` if we treated the inner `{{ }}` as ours. Better to resolve it
  // and let the unknown root complain loudly than to half-support another tool's syntax.
  t.exception(() => interpolate('${{ github.sha }}', SCOPE), /unknown reference root "github"/)
})

test('ROOTS is the closed set, and it is what the errors advertise', (t) => {
  t.alike(ROOTS, ['target', 'matrix', 'env', 'needs', 'steps', 'job', 'run'])
  try {
    interpolate('{{ nope.x }}', SCOPE)
  } catch (err) {
    for (const root of ROOTS) t.ok(err.message.includes(root), root + ' is advertised')
  }
})

// --- conditions ------------------------------------------------------------------------

test('an absent condition means success()', (t) => {
  t.ok(evaluate(null, SCOPE, {}), 'null')
  t.ok(evaluate('', SCOPE, {}), 'empty')
  t.ok(evaluate(undefined, SCOPE, {}), 'undefined')
})

test('status functions reflect the run so far', (t) => {
  t.ok(evaluate('success()', SCOPE, {}))
  t.absent(evaluate('success()', SCOPE, { failed: true }))
  t.ok(evaluate('failure()', SCOPE, { failed: true }))
  t.absent(evaluate('failure()', SCOPE, {}))
  t.ok(evaluate('always()', SCOPE, { failed: true }), 'always() ignores everything')
  t.ok(evaluate('cancelled()', SCOPE, { cancelled: true }))
  t.absent(
    evaluate('failure()', SCOPE, { failed: true, cancelled: true }),
    'a cancel is not a failure'
  )
  t.alike(STATUS_FNS, ['success', 'failure', 'always', 'cancelled'])
})

test('comparison, membership, and boolean composition', (t) => {
  t.ok(evaluate("target.platform == 'linux'", SCOPE, {}))
  t.absent(evaluate("target.platform == 'darwin'", SCOPE, {}))
  t.ok(evaluate("target.platform != 'win32'", SCOPE, {}))
  t.ok(evaluate("target.platform in ['linux', 'darwin']", SCOPE, {}))
  t.absent(evaluate("target.platform in ['win32']", SCOPE, {}))
  t.ok(evaluate("success() and target.arch == 'x64'", SCOPE, {}))
  t.absent(evaluate("failure() and target.arch == 'x64'", SCOPE, {}))
  t.ok(evaluate("failure() or target.arch == 'x64'", SCOPE, {}))
  t.ok(evaluate('not failure()', SCOPE, {}))
  t.ok(evaluate('(failure() or success()) and not cancelled()', SCOPE, {}))
})

test('conditions read paths without braces', (t) => {
  // Wrapping a path in {{ }} inside a condition reads badly and buys nothing.
  t.ok(evaluate("needs.version.outputs.value == '1.2.3'", SCOPE, {}))
  t.ok(evaluate("env.APP == 'MyApp'", SCOPE, {}))
})

test('unknown references in a condition also throw', (t) => {
  t.exception(() => evaluate("env.NOPE == 'x'", SCOPE, {}), /unknown reference/)
  t.exception(() => evaluate('secrets.TOKEN', SCOPE, {}), /unknown reference root/)
})

test('the things we did not build are rejected, not half-supported', (t) => {
  const rejected = [
    "hashFiles('**/x')",
    'toJSON(env)',
    'contains(env.APP, "My")',
    '1 + 1',
    "env.APP =~ 'My'",
    "env.APP && 'x'",
    "target.platform == 'linux' &&",
    "'unterminated"
  ]
  for (const src of rejected) {
    t.exception(() => evaluate(src, SCOPE, {}), /EXPR_INVALID|EXPR_UNKNOWN_REFERENCE/, src)
  }
})

test('truthiness is explicit', (t) => {
  t.ok(truthy(true))
  t.ok(truthy('yes'))
  t.absent(truthy(false))
  t.absent(truthy(''))
  t.absent(truthy('false'), 'the string "false" is falsy, because env vars are strings')
  t.absent(truthy('0'))
  t.absent(truthy(null))
  t.absent(truthy(undefined))
})
