'use strict'

// Assertion helpers that turn a MISSING thing into a failed assertion instead of a dead suite.
//
// Both of these exist for the same measured reason. brittle runs each test file in one process, and
// an exception thrown outside an assertion is an unhandled rejection that kills the whole run -- so
// a single unexpected failure takes down every test after it, and the output blames whatever
// happened to be last. Observed twice for real in this project: a base image swapped out mid-run
// took the suite down at test 236 of 290, and on the first macOS run an ENOENT on /etc/hostname
// killed it at test 165 of 290, hiding the entire escape suite.
//
// The rule: anything that reads a run's output has to assume the run might have produced nothing.

// A required event from a --json stream.
function need(t, evs, pred, what) {
  const found = evs.find(pred)
  t.ok(found, `event present: ${what}`)
  return found || { data: {} }
}

// The run ids under a state directory. Returns [] rather than throwing when the run never got far
// enough to write any state, which is exactly the situation where the caller is about to index [0].
function runIds(t, fs, state) {
  let ids = []
  try {
    ids = fs.readdirSync(state + '/runs')
  } catch (err) {
    t.fail(`no run state under ${state}/runs (${err.code || err.message}) -- the run wrote nothing`)
    return []
  }
  t.ok(ids.length > 0, `the run wrote state: ${ids.join(', ') || '(none)'}`)
  return ids
}

// The single run id a test expects, or null with a failed assertion.
function runId(t, fs, state) {
  const ids = runIds(t, fs, state)
  return ids.length ? ids[0] : null
}

module.exports = { need, runIds, runId }
