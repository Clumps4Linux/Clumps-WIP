# Clumps Formal Specification

This directory contains an experimental formal specification of the
security-state semantics of Clumps.

The specification is intentionally abstract. It does not attempt to model
Linux seccomp-BPF, Landlock, kernel internals, or the generated BPF programs.

Instead, it describes the security properties that the Clumps implementation
is intended to preserve.

## Purpose

The first goal is not to prove that Clumps is secure.

The first goal is to make the intended semantics explicit.

In particular, the model provides a place to state and mechanically explore
properties that are otherwise distributed across:

- `clumps.h`
- inline implementation comments
- the test suite
- the project README
- Linux seccomp behavior
- Linux Landlock behavior

This should help distinguish:

1. intended Clumps semantics,
2. implementation details,
3. Linux-specific limitations.

## Model

`Clumps.tla` models a Clumps process as a security state containing:

- the currently enforced pledge policy,
- the stored exec pledge policy,
- unveil rules,
- the unveil lock state,
- policy-installation state,
- parent/child policy state.

The model deliberately uses finite sets of abstract promises, paths, and
permissions.

The concrete names in `Clumps.cfg` are representative only. They are not
intended to constitute the complete Clumps promise vocabulary or Landlock
permission set.

## Initial invariants

The current model explores the following properties.

### Pledge contraction

A pledge operation may remove promises but cannot add promises that were not
already present.

Conceptually:

    new_pledge ⊆ current_pledge

### Exec contraction

An exec pledge may not contain promises outside the policy currently enforced
by the process.

    exec_pledge ⊆ enforced_pledge

### Unveil monotonicity

Repeated unveil operations intersect permissions rather than expanding them.

    new_permissions = old_permissions ∩ requested_permissions

This captures the intended restriction-oriented behavior of repeated unveil
rules.

### Irreversible unveil locking

Once unveil policy is locked, it cannot subsequently be modified.

    locked => policy remains unchanged

### Successful installation consistency

When policy installation succeeds, the policy recorded as installed must agree
with the policy actually considered enforced by the abstract model.

### Failed installation does not advance state

A failed security-policy installation must not cause internal bookkeeping to
claim that the new policy is enforced.

This is particularly important because a security library must avoid situations
where its internal representation becomes more restrictive than the actual
kernel enforcement state.

### Child contraction

A child may contract inherited policy, but may not expand it.

    child_policy ⊆ parent_policy

## What this model does not currently specify

The model does not yet define:

- the exact syscall membership of each pledge promise;
- the exact seccomp action for each denied syscall;
- signal/errno behavior;
- Landlock ABI versions;
- filesystem path resolution;
- `realpath()` behavior;
- symlink races;
- file descriptor semantics;
- network address semantics;
- Linux namespace behavior;
- `fork()`/`clone()` details;
- `execve()` behavior at the kernel level;
- seccomp filter inheritance;
- kernel-specific behavior;
- architecture-specific syscall numbering;
- the exact relationship between pledge promises and Landlock rules.

Those should be added only after the abstract security semantics are stable.

## Suggested workflow

The intended workflow is:

    C implementation
          |
          v
    observed invariants
          |
          v
    abstract TLA+ model
          |
          v
    TLC exploration
          |
          v
    semantic corrections
          |
          v
    implementation tests
          |
          v
    eventual refinement model

The TLA+ model should therefore not be treated as a translation of the C
implementation.

It is a separate statement of what the implementation is supposed to mean.

## TLC

With a TLA+ installation, the model can be opened in the TLA+ Toolbox or
VS Code extension and checked with TLC using `Clumps.cfg`.

Because the model uses finite sets, TLC can exhaustively explore the bounded
state space selected by the configuration.

The constants in `Clumps.cfg` are intentionally small.

As the model becomes more precise, additional constants or symmetry
reductions may be introduced to keep the state space manageable.

## Refinement

A future version may introduce a second specification describing the Linux
implementation more concretely.

A possible structure is:

    Clumps.tla
        |
        | abstract security semantics
        v
    ClumpsLinux.tla
        |
        | seccomp/Landlock correspondence
        v
    clumps.h

The eventual objective would be to establish that the concrete implementation
does not violate the security invariants of the abstract specification.

That is a substantially stronger claim than simply checking that the current
C implementation behaves as expected in its existing tests.

## Status

This specification is experimental and should be considered part of the
design process rather than a security proof.

If the implementation and this model disagree, that disagreement should be
treated as useful information: either the implementation, the model, or the
intended semantics need clarification.
