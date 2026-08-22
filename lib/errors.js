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

  static UNKNOWN_TOOLCHAIN(msg) {
    return new WorkflowError(msg, WorkflowError.UNKNOWN_TOOLCHAIN)
  }

  static TOOLCHAIN_NOT_BUILT(msg) {
    return new WorkflowError(msg, WorkflowError.TOOLCHAIN_NOT_BUILT)
  }

  static UNKNOWN_TIER(msg) {
    return new WorkflowError(msg, WorkflowError.UNKNOWN_TIER)
  }

  static ISOLATION_UNAVAILABLE(msg) {
    return new WorkflowError(msg, WorkflowError.ISOLATION_UNAVAILABLE)
  }

  // An image built for an architecture the container runtime is not. Distinct from
  // ISOLATION_UNAVAILABLE because the isolation is fine -- it is the WORKLOAD that would be
  // emulated, which decision 2 refuses. See lib/isolation/arch.js.
  static IMAGE_ARCH_MISMATCH(msg) {
    return new WorkflowError(msg, WorkflowError.IMAGE_ARCH_MISMATCH)
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

  // --- expressions ----------------------------------------------------------------------

  static EXPR_UNKNOWN_REFERENCE(msg) {
    return new WorkflowError(msg, WorkflowError.EXPR_UNKNOWN_REFERENCE)
  }

  static EXPR_INVALID(msg) {
    return new WorkflowError(msg, WorkflowError.EXPR_INVALID)
  }

  // --- graph ----------------------------------------------------------------------------

  static CYCLE(msg) {
    return new WorkflowError(msg, WorkflowError.CYCLE)
  }

  // --- transfer -------------------------------------------------------------------------

  static TRANSFER_REJECTED(msg) {
    return new WorkflowError(msg, WorkflowError.TRANSFER_REJECTED)
  }

  // --- artifacts ------------------------------------------------------------------------

  static ARTIFACT_EMPTY(msg) {
    return new WorkflowError(msg, WorkflowError.ARTIFACT_EMPTY)
  }

  static ARTIFACT_MISSING(msg) {
    return new WorkflowError(msg, WorkflowError.ARTIFACT_MISSING)
  }

  static AGENT_TOO_OLD(msg) {
    return new WorkflowError(msg, WorkflowError.AGENT_TOO_OLD)
  }

  // --- prefetch -------------------------------------------------------------------------

  static PREFETCH_INVALID(msg) {
    return new WorkflowError(msg, WorkflowError.PREFETCH_INVALID)
  }

  static PREFETCH_FAILED(msg) {
    return new WorkflowError(msg, WorkflowError.PREFETCH_FAILED)
  }

  // --- runner config and publishing -----------------------------------------------------

  static CONFIG_MISSING(msg) {
    return new WorkflowError(msg, WorkflowError.CONFIG_MISSING)
  }

  static CONFIG_INVALID(msg) {
    return new WorkflowError(msg, WorkflowError.CONFIG_INVALID)
  }

  static CONFIG_INSECURE(msg) {
    return new WorkflowError(msg, WorkflowError.CONFIG_INSECURE)
  }

  static PUBLISH_REFUSED(msg) {
    return new WorkflowError(msg, WorkflowError.PUBLISH_REFUSED)
  }

  static PUBLISH_FAILED(msg) {
    return new WorkflowError(msg, WorkflowError.PUBLISH_FAILED)
  }

  // --- seccomp -------------------------------------------------------------------------

  static SECCOMP_BASE_MISSING(msg) {
    return new WorkflowError(msg, WorkflowError.SECCOMP_BASE_MISSING)
  }

  static SECCOMP_INVALID(msg) {
    return new WorkflowError(msg, WorkflowError.SECCOMP_INVALID)
  }
}
