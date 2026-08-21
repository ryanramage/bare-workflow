// Error type for the whole project.
//
// Follows the bare-tcp convention: one Error subclass, with static factory methods whose
// function name IS the error code. That keeps codes and constructors impossible to drift apart,
// and means `err.code` is always a real, greppable identifier rather than a free-form string.

module.exports = class WorkflowError extends Error {
  constructor(msg, fn = WorkflowError, code = fn.name) {
    super(`${code}: ${msg}`)
    this.code = code
    if (Error.captureStackTrace) Error.captureStackTrace(this, fn)
  }

  get name() {
    return 'WorkflowError'
  }

  // --- isolation / argv construction ---------------------------------------------------

  static FORBIDDEN_FLAG(msg) {
    return new WorkflowError(msg, WorkflowError.FORBIDDEN_FLAG)
  }

  static HOST_MOUNT_REFUSED(msg) {
    return new WorkflowError(msg, WorkflowError.HOST_MOUNT_REFUSED)
  }

  static IMAGE_NOT_PINNED(msg) {
    return new WorkflowError(msg, WorkflowError.IMAGE_NOT_PINNED)
  }

  static INVALID_SPEC(msg) {
    return new WorkflowError(msg, WorkflowError.INVALID_SPEC)
  }

  static UNKNOWN_TIER(msg) {
    return new WorkflowError(msg, WorkflowError.UNKNOWN_TIER)
  }

  static ISOLATION_UNAVAILABLE(msg) {
    return new WorkflowError(msg, WorkflowError.ISOLATION_UNAVAILABLE)
  }

  // --- schema / targets -----------------------------------------------------------------

  static SCHEMA_INVALID(msg) {
    return new WorkflowError(msg, WorkflowError.SCHEMA_INVALID)
  }

  static SCHEMA_VERSION(msg) {
    return new WorkflowError(msg, WorkflowError.SCHEMA_VERSION)
  }

  static SCHEMA_SYNTAX(msg) {
    return new WorkflowError(msg, WorkflowError.SCHEMA_SYNTAX)
  }

  static UNKNOWN_TARGET(msg) {
    return new WorkflowError(msg, WorkflowError.UNKNOWN_TARGET)
  }

  static TARGET_UNSATISFIABLE(msg) {
    return new WorkflowError(msg, WorkflowError.TARGET_UNSATISFIABLE)
  }

  // --- seccomp -------------------------------------------------------------------------

  static SECCOMP_BASE_MISSING(msg) {
    return new WorkflowError(msg, WorkflowError.SECCOMP_BASE_MISSING)
  }

  static SECCOMP_INVALID(msg) {
    return new WorkflowError(msg, WorkflowError.SECCOMP_INVALID)
  }
}
