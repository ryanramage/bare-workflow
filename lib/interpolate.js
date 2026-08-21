'use strict'

// `{{ path }}` interpolation and the `if:` predicate evaluator.
//
// Deliberately tiny. wrkflw's GHA-compatible evaluator is ~1050 hand-written lines of tokenizer and
// recursive-descent parser across twelve contexts; this gets the useful ~95% for a fraction of it,
// and skipping the general expression language removes a whole class of injection bug.
//
// Two rules matter more than the syntax:
//
//   * AN UNKNOWN PATH IS A HARD ERROR, not the empty string. GHA's silent-empty-string is the single
//     largest source of mystery CI failures -- `{{ matrix.nodee }}` should fail loudly at plan time,
//     not produce a build that quietly does the wrong thing.
//   * The scope is a CLOSED set of roots. There is no way to reach arbitrary state, so what a
//     workflow can read is reviewable by looking at this file.
//
// Syntax is `{{ }}` rather than GHA's `${{ }}`: unambiguous inside a `run:` body and it never
// collides with shell `${...}` or `$(...)`.

const WorkflowError = require('./errors.js')

const ROOTS = ['target', 'matrix', 'env', 'needs', 'steps', 'job', 'run']

const PATTERN = /\{\{([^}]*)\}\}/g

// --- scope resolution ------------------------------------------------------------------

// Resolve a dotted path against the scope. Returns a string; throws on anything unknown.
function resolvePath(path, scope) {
  const parts = path.split('.').map((p) => p.trim())
  if (parts.some((p) => p === '')) {
    throw WorkflowError.EXPR_INVALID(`malformed reference ${JSON.stringify(path)}`)
  }

  const [root, ...rest] = parts
  if (!ROOTS.includes(root)) {
    throw WorkflowError.EXPR_UNKNOWN_REFERENCE(
      `unknown reference root ${JSON.stringify(root)} in ${JSON.stringify(path)}; ` +
        `available: ${ROOTS.join(', ')}`
    )
  }

  let node = scope[root]
  if (node === undefined) {
    throw WorkflowError.EXPR_UNKNOWN_REFERENCE(
      `${JSON.stringify(root)} is not available here (in ${JSON.stringify(path)})`
    )
  }

  // `{{ target }}` on its own is the target name -- the common case, and worth not making people
  // write `target.name`.
  if (rest.length === 0) {
    if (typeof node === 'object' && node !== null) {
      if (typeof node.name === 'string') return node.name
      throw WorkflowError.EXPR_UNKNOWN_REFERENCE(
        `${JSON.stringify(path)} refers to a group, not a value; try one of: ${Object.keys(node).join(', ')}`
      )
    }
    return String(node)
  }

  const walked = [root]
  for (const key of rest) {
    walked.push(key)
    if (node === null || typeof node !== 'object' || !(key in node)) {
      throw WorkflowError.EXPR_UNKNOWN_REFERENCE(
        `unknown reference ${JSON.stringify(walked.join('.'))}` +
          (node && typeof node === 'object'
            ? `; available: ${Object.keys(node).join(', ') || '(none)'}`
            : '')
      )
    }
    node = node[key]
  }

  if (node === null || node === undefined) return ''
  if (typeof node === 'object') {
    throw WorkflowError.EXPR_UNKNOWN_REFERENCE(
      `${JSON.stringify(path)} refers to a group, not a value; try one of: ${Object.keys(node).join(', ')}`
    )
  }
  return String(node)
}

// Replace every `{{ ... }}` in a string.
function interpolate(text, scope) {
  if (typeof text !== 'string') return text
  if (text.indexOf('{{') === -1) return text

  // An unclosed `{{` is a typo, not an instruction to leave it alone.
  const opens = (text.match(/\{\{/g) || []).length
  const closes = (text.match(/\}\}/g) || []).length
  if (opens !== closes) {
    throw WorkflowError.EXPR_INVALID(`unbalanced {{ }} in ${JSON.stringify(trunc(text))}`)
  }

  return text.replace(PATTERN, (_, inner) => resolvePath(inner.trim(), scope))
}

function trunc(s) {
  return s.length > 60 ? s.slice(0, 57) + '...' : s
}

// --- the `if:` predicate ---------------------------------------------------------------
//
// Grammar, and nothing beyond it:
//
//   expr    := or
//   or      := and ('or' and)*
//   and     := unary ('and' unary)*
//   unary   := 'not' unary | '(' expr ')' | comparison
//   compare := term (('=='|'!=') term | 'in' '[' term,* ])?
//   term    := path | 'literal' | status()
//
// Paths are written bare inside `if:` (`target.platform != 'win32'`), because wrapping them in
// `{{ }}` inside a condition reads badly and serves no purpose.

const STATUS_FNS = ['success', 'failure', 'always', 'cancelled']

function tokenize(src) {
  const tokens = []
  let i = 0
  while (i < src.length) {
    const c = src[i]
    if (/\s/.test(c)) {
      i++
      continue
    }
    if (c === '(' || c === ')' || c === '[' || c === ']' || c === ',') {
      tokens.push({ type: c })
      i++
      continue
    }
    if (c === "'") {
      const end = src.indexOf("'", i + 1)
      if (end === -1) {
        throw WorkflowError.EXPR_INVALID(`unterminated string in condition: ${JSON.stringify(src)}`)
      }
      tokens.push({ type: 'string', value: src.slice(i + 1, end) })
      i = end + 1
      continue
    }
    if (src.startsWith('==', i) || src.startsWith('!=', i)) {
      tokens.push({ type: src.slice(i, i + 2) })
      i += 2
      continue
    }
    const word = /^[A-Za-z_][A-Za-z0-9_.\-]*/.exec(src.slice(i))
    if (word) {
      const value = word[0]
      if (value === 'and' || value === 'or' || value === 'not' || value === 'in') {
        tokens.push({ type: value })
      } else {
        tokens.push({ type: 'word', value })
      }
      i += value.length
      continue
    }
    throw WorkflowError.EXPR_INVALID(
      `unexpected ${JSON.stringify(c)} in condition ${JSON.stringify(src)}; ` +
        'conditions support ==, !=, in, and, or, not, parentheses and quoted strings'
    )
  }
  return tokens
}

function evaluate(condition, scope, status = {}) {
  if (condition === null || condition === undefined || String(condition).trim() === '') return true

  const tokens = tokenize(String(condition))
  let pos = 0

  const peek = () => tokens[pos]
  const next = () => tokens[pos++]
  const expect = (type) => {
    const t = next()
    if (!t || t.type !== type) {
      throw WorkflowError.EXPR_INVALID(`expected ${type} in condition ${JSON.stringify(condition)}`)
    }
    return t
  }

  function parseTerm() {
    const t = next()
    if (!t) {
      throw WorkflowError.EXPR_INVALID(`condition ends unexpectedly: ${JSON.stringify(condition)}`)
    }
    if (t.type === 'string') return { kind: 'literal', value: t.value }
    if (t.type !== 'word') {
      throw WorkflowError.EXPR_INVALID(`expected a value in condition ${JSON.stringify(condition)}`)
    }
    // A status function call.
    if (peek() && peek().type === '(') {
      next()
      expect(')')
      if (!STATUS_FNS.includes(t.value)) {
        throw WorkflowError.EXPR_INVALID(
          `unknown function ${JSON.stringify(t.value + '()')}; available: ${STATUS_FNS.map((f) => f + '()').join(', ')}`
        )
      }
      return { kind: 'status', name: t.value }
    }
    return { kind: 'path', path: t.value }
  }

  function parseCompare() {
    if (peek() && peek().type === '(') {
      next()
      const inner = parseOr()
      expect(')')
      return inner
    }
    const left = parseTerm()
    const op = peek()
    if (op && (op.type === '==' || op.type === '!=')) {
      next()
      return { kind: 'compare', op: op.type, left, right: parseTerm() }
    }
    if (op && op.type === 'in') {
      next()
      expect('[')
      const list = []
      if (peek() && peek().type !== ']') {
        list.push(parseTerm())
        while (peek() && peek().type === ',') {
          next()
          list.push(parseTerm())
        }
      }
      expect(']')
      return { kind: 'in', left, list }
    }
    return left
  }

  function parseUnary() {
    if (peek() && peek().type === 'not') {
      next()
      return { kind: 'not', operand: parseUnary() }
    }
    return parseCompare()
  }

  function parseAnd() {
    let node = parseUnary()
    while (peek() && peek().type === 'and') {
      next()
      node = { kind: 'and', left: node, right: parseUnary() }
    }
    return node
  }

  function parseOr() {
    let node = parseAnd()
    while (peek() && peek().type === 'or') {
      next()
      node = { kind: 'or', left: node, right: parseAnd() }
    }
    return node
  }

  const ast = parseOr()
  if (pos !== tokens.length) {
    throw WorkflowError.EXPR_INVALID(
      `unexpected trailing input in condition ${JSON.stringify(condition)}`
    )
  }
  return truthy(run(ast))

  function run(node) {
    switch (node.kind) {
      case 'literal':
        return node.value
      case 'path':
        return resolvePath(node.path, scope)
      case 'status':
        return statusValue(node.name, status)
      case 'compare': {
        const eq = String(run(node.left)) === String(run(node.right))
        return node.op === '==' ? eq : !eq
      }
      case 'in': {
        const v = String(run(node.left))
        return node.list.some((item) => String(run(item)) === v)
      }
      case 'not':
        return !truthy(run(node.operand))
      case 'and':
        return truthy(run(node.left)) && truthy(run(node.right))
      case 'or':
        return truthy(run(node.left)) || truthy(run(node.right))
      default:
        throw WorkflowError.EXPR_INVALID('unreachable condition node')
    }
  }
}

// `status` describes the run so far: { failed: bool, cancelled: bool }.
function statusValue(name, status) {
  switch (name) {
    case 'always':
      return true
    case 'cancelled':
      return !!status.cancelled
    case 'failure':
      return !!status.failed && !status.cancelled
    case 'success':
      // The default when no `if:` is given, so it must mean "nothing has gone wrong yet".
      return !status.failed && !status.cancelled
    default:
      return false
  }
}

function truthy(v) {
  if (typeof v === 'boolean') return v
  if (v === undefined || v === null) return false
  const s = String(v)
  return s !== '' && s !== 'false' && s !== '0'
}

module.exports = { interpolate, evaluate, resolvePath, truthy, ROOTS, STATUS_FNS }
