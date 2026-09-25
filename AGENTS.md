# AGENTS.md — Clumps4Linux

## Project Overview

Clumps4Linux is a single-header C library providing OpenBSD-style `pledge()` and `unveil()` semantics on Linux.

The implementation uses:

- **seccomp-BPF** for syscall restrictions.
- **Landlock LSM** for filesystem and supported network restrictions.
- Linux-specific syscalls, APIs, and kernel behavior.
- C11 with GNU extensions (`-std=gnu11`).

Supported target architectures:

- x86_64
- aarch64
- riscv64

This is a security-oriented systems project. Changes must therefore be evaluated for their effect on **security semantics**, not merely whether they compile or make tests pass.

---

## Current Development State

This repository is a **work in progress**.

The current source represents a substantial refactor that has not yet been fully verified on Linux.

### Current priority

**Do not perform further architectural refactoring until the current source builds successfully on Linux and the integrated test suite passes.**

The immediate development sequence is:

1. Build the current source on Linux.
2. Resolve compilation and linker failures.
3. Run the integrated test suite.
4. Diagnose and fix test failures.
5. Establish a known-good baseline.
6. Only then resume feature development or further architectural changes.

Do not use the absence of Linux verification as an excuse to redesign code preemptively.

---

## Change Discipline

When working on the current refactor:

### Fix, don't redesign

If compilation or tests reveal a problem introduced by the refactor:

- Fix the actual problem.
- Keep the existing intended architecture.
- Avoid unrelated cleanup.
- Avoid opportunistic API changes.
- Avoid rewriting working code merely because another implementation looks nicer.
- Do not change test expectations simply to make tests pass.

If you identify a potentially useful redesign that is unrelated to the immediate failure, document it separately rather than implementing it.

### Minimize the diff

Prefer the smallest change that correctly resolves the observed problem.

Do not combine:

- bug fixes with unrelated refactoring;
- formatting changes with behavioral changes;
- API redesign with test repairs;
- portability work with Linux-specific security changes.

A small, understandable security diff is preferable to a broad "improvement."

---

## Security-Critical Code

Treat the following areas as security-sensitive:

- seccomp filter construction;
- syscall allow/deny rules;
- seccomp fail actions;
- `PR_SET_NO_NEW_PRIVS`;
- Landlock ruleset construction;
- Landlock ABI detection;
- filesystem permission translation;
- network permission translation;
- pledge promise parsing;
- exec-promise contraction;
- filter layering;
- fork/exec behavior;
- W^X enforcement;
- file descriptor handling;
- resource-limit handling;
- namespace-related isolation;
- canonicalization of unveiled paths.

Before changing security-sensitive code, determine:

1. What security property the existing code is attempting to enforce.
2. Which kernel mechanism actually enforces it.
3. Whether the change alters the set of operations permitted or denied.
4. Whether behavior differs across supported kernel versions or Landlock ABIs.
5. Whether the integrated tests cover the affected behavior.

Never assume that a more restrictive-looking implementation is automatically correct. Pledge and unveil semantics have deliberate interactions and approximations.

---

## Monotonic Security Model

Clumps4Linux relies on Linux security mechanisms whose restrictions are generally monotonic.

In particular:

- seccomp filters are additive;
- layered filters cannot restore permissions removed by earlier filters;
- pledge promises cannot be expanded after the initial pledge;
- exec-promises are intended to contract permissions;
- Landlock is an allow-list mechanism;
- unveiled permissions are intersected on repeated rules.

Do not introduce code that accidentally attempts to expand an already-installed security policy.

When changing filter construction, reason about the **intersection of all active restrictions**, not just the newest filter.

---

## Critical Lifecycle Rules

For filesystem-related promises:

```text
lunveil()
    ↓
lunveil_lock()
    ↓
install_pledge()
```

`lunveil_lock()` must occur before `install_pledge()` when filesystem promises such as the following are used:

- `rpath`
- `wpath`
- `cpath`
- `exec`
- `tmppath`
- `getpw`

Do not reorder this lifecycle without understanding the implementation's dependency between Landlock and pledge installation.

### Exec contracts

The intended model is:

```text
Parent:
    install_pledge(promises, execpromises)

Child:
    install_pledge_exec(execpromises)
    execve(...)
```

`execpromises` must be a subset of the parent's effective promises.

Use `clump_execve()` when appropriate to avoid forgetting the child contraction.

Remember that seccomp filters are inherited across `fork()` and are additive. A child contract does not automatically create progressively tighter contracts for every future descendant.

---

## Failure Semantics

Do not silently change failure behavior.

Clumps4Linux may use different seccomp fail actions depending on configuration, including debug behavior such as:

```c
SCMP_ACT_ERRNO(EPERM)
```

The contracted filter must preserve the intended fail-action policy of the initial pledge where required by the existing implementation.

Do not replace an intentional `EPERM` failure with process termination, or vice versa, merely because one is easier to test.

---

## Landlock Compatibility

Landlock functionality depends on the kernel ABI.

Known feature boundaries documented by the project include:

| Feature | Minimum Kernel | Landlock ABI |
|---|---:|---:|
| Filesystem restrictions | 5.13 | 1 |
| Cross-directory rename/link | 5.19 | 2 |
| File truncate | 6.2 | 3 |
| TCP network | 6.7 | 4 |
| Device ioctl restrictions | 6.10 | 5 |
| Abstract UNIX / signal scoping | 6.12 | 6 |
| Audit log control | 6.13 | 7 |
| MT enforcement improvements | 7.0 | 8 |
| Pathname UNIX socket | 7.1 | 9 |
| UDP network + QUIET flags | 7.2 | 10 |

Do not assume that the newest Landlock ABI is available.

Code interacting with Landlock must handle feature detection appropriately.

Use:

```c
clumps_get_landlock_abi()
```

rather than assuming a particular kernel version from the userspace environment.

---

## Graceful Fallback

Kernels below Landlock ABI 1 cannot provide the project's path-based filesystem restrictions.

If graceful fallback is enabled, Clumps4Linux may continue with seccomp-only restrictions.

Do not describe seccomp-only mode as equivalent to full pledge/unveil behavior.

In particular:

> Seccomp cannot enforce arbitrary pathname-based access control.

Any fallback behavior must be explicit and must not silently claim to provide protections that are unavailable.

---

## Known Security Limitations

The existing design intentionally documents limitations. Do not remove these limitations from documentation merely because the implementation appears to work in ordinary tests.

Known limitations include:

- TOCTOU windows associated with path canonicalization.
- Landlock's inability to subtract permissions from an already-allowed ancestor.
- Grandchild contract limitations.
- Resource exhaustion without separate resource limits.
- Namespace escape concerns.
- W^X limitations involving `brk()`.
- W^X limitations involving `mremap()`.
- Broad ioctl access when the `ioctl` promise is used.
- Kernel-dependent Landlock functionality.
- Unsupported ICMP/raw-socket restrictions.
- Network restrictions being limited to supported bind/connect operations.

If a change claims to eliminate one of these limitations, require a concrete implementation and test demonstrating that the limitation has actually been removed.

---

## Promise Semantics

Do not casually modify the meaning of an existing promise.

Current promises include:

```text
stdio
rpath
wpath
cpath
tmppath
getpw
inet
dns
unix
exec
proc
id
ioctl
tty
io_uring
fattr
recvfd
sendfd
```

When adding or modifying a promise:

1. Define its intended semantics.
2. Identify the relevant syscalls.
3. Identify any Landlock implications.
4. Consider interactions with existing promises.
5. Add or update tests.
6. Update the documentation.

Special interactions already documented include:

- `ioctl` superseding the narrower `stdio` ioctl subset.
- `getpw` being close to `rpath` at the seccomp layer.
- `tty` allowing `openat`/`openat2` at the seccomp layer while Landlock still controls actual path access.

---

## Single-Header Architecture

Clumps4Linux is intentionally distributed as a single header.

The implementation convention is:

```c
#define CLUMPS_IMPLEMENTATION
#include "clumps.h"
```

The implementation must be instantiated in exactly one translation unit.

Do not casually split the implementation into multiple source files or introduce a build system dependency merely to make development more convenient.

A major architectural change to the single-header model requires explicit justification.

---

## Compiler Requirements

The project targets:

- GCC 7.0+
- Clang 5.0+
- C11 with GNU extensions

Use:

```text
-std=gnu11
```

Do not introduce strict-ISO-only assumptions.

The project does not currently support:

- MSVC
- Intel ICC
- TenDRA C
- strict ISO C mode (`-pedantic`)

Compiler diagnostics should be treated seriously, particularly:

```text
-Wall
-Wextra
-Werror=unused-result
```

Do not suppress a warning globally to hide a newly introduced problem.

---

## Build and Test Expectations

The baseline build is approximately:

```sh
gcc -O2 -Wall -Wextra -Werror=unused-result -std=gnu11 \
    main.c -o my_app -lseccomp -lpthread
```

The integrated test harness is built approximately as:

```sh
gcc -O2 -Wall -Wextra -Werror=unused-result -std=gnu11 \
    -DCLUMPS_TESTS clumps.h -o clumps_test -lseccomp -lpthread
```

Run:

```sh
./clumps_test
```

Each test is expected to isolate security state appropriately, since seccomp restrictions cannot simply be removed from a process once installed.

### Test modifications

Do not weaken or remove security tests to make the suite pass.

When a test fails:

1. Determine whether the implementation is wrong.
2. Determine whether the test is wrong.
3. Determine whether the behavior is kernel-version dependent.
4. Determine whether the behavior is intentionally approximated.
5. Only then modify code or tests.

---

## Linux Environment

macOS is a development workstation, not the target platform.

Do not assume that successful reasoning, parsing, or editing on macOS constitutes a successful build.

The authoritative build/test environment is Linux.

The project targets multiple architectures, including:

- x86_64
- aarch64
- riscv64

An amd64 Linux build establishes Linux correctness but does not by itself establish architecture coverage for aarch64 or riscv64.

When architecture-specific behavior is suspected, test on the relevant architecture rather than assuming portability.

---

## Kernel Testing

Do not infer kernel feature availability from the compiler or libc version.

Where behavior depends on Landlock or another kernel facility:

- query the running kernel;
- detect the relevant ABI;
- test the actual behavior;
- distinguish unavailable functionality from implementation failure.

A test passing on one kernel does not prove identical behavior on all supported kernels.

---

## Error Handling

Clumps4Linux is a low-level security library.

Do not ignore return values from security-related operations.

In particular, pay attention to:

- `lunveil()`
- `lunveil_net()`
- `lunveil_lock()`
- `lunveil_lock_ext()`
- `install_pledge()`
- `install_pledge_exec()`
- `clump_execve()`
- `clumps_close_extra_fds()`
- `clumps_set_resource_limits()`

Do not turn a failed security operation into a successful return merely to improve application compatibility.

A security restriction that failed to install is not equivalent to a restriction that successfully installed.

---

## Documentation Requirements

When changing externally visible behavior, update the relevant documentation.

Documentation should accurately distinguish:

- what Clumps4Linux intends to provide;
- what seccomp provides;
- what Landlock provides;
- what depends on kernel ABI;
- what is only an approximation of OpenBSD semantics;
- what is explicitly not covered.

Avoid marketing language that implies stronger security guarantees than the implementation provides.

---

## API Stability

Existing public API names and semantics should be treated as stable unless the current development task explicitly concerns an API change.

Before changing a public function:

1. Search the repository for all uses.
2. Check integrated tests.
3. Check documentation.
4. Consider source compatibility.
5. Consider behavioral compatibility.
6. Document intentional incompatibilities.

Do not rename public APIs as part of unrelated cleanup.

---

## Git Discipline

Keep commits logically focused.

Prefer commits such as:

```text
fix: correct Landlock ABI detection
test: cover exec promise contraction
fix: preserve seccomp fail action for child contracts
docs: clarify graceful fallback behavior
```

Avoid commits that combine unrelated changes.

Before committing:

```text
git diff
git status
```

Review the actual diff rather than relying on the agent's description of its changes.

Never commit generated files, credentials, private keys, local machine configuration, or unrelated personal data.

---

## Agent Workflow

For any development task:

### Before changing code

1. Read the relevant source.
2. Search for all callers and related definitions.
3. Read the relevant tests.
4. Read the relevant documentation.
5. Identify kernel/API dependencies.
6. State the intended behavioral change internally before implementing it.

### While changing code

1. Make the smallest appropriate change.
2. Preserve existing security semantics.
3. Do not introduce unrelated refactoring.
4. Keep error handling explicit.
5. Add tests for genuinely new behavior.

### After changing code

1. Inspect the diff.
2. Build on Linux.
3. Run the relevant tests.
4. Run the integrated test suite when practical.
5. Report failures honestly.
6. Do not claim success without actually running the relevant command.

---

## Review Mode

When asked to **review** code, do not automatically rewrite it.

Review in this order:

1. Security correctness.
2. Semantic correctness.
3. Kernel/API compatibility.
4. Error handling.
5. Concurrency and lifecycle behavior.
6. Resource management.
7. Test coverage.
8. Portability across supported Linux architectures.
9. Maintainability and style.

For each finding, provide:

- **Severity:** critical / high / medium / low / informational.
- **Location:** file and relevant function/section.
- **Problem:** what is wrong or potentially wrong.
- **Impact:** what could happen.
- **Evidence:** why the concern exists.
- **Suggested fix:** only when appropriate.

Do not manufacture findings simply to produce a longer review.

If no significant issues are found, say so.

---

## Security Review Standard

For security-sensitive findings, distinguish clearly between:

- a demonstrated vulnerability;
- a plausible security weakness;
- a portability issue;
- a semantic mismatch with OpenBSD;
- a hardening opportunity;
- a documentation problem.

Do not call something a vulnerability merely because it is theoretically unusual.

Conversely, do not dismiss a security issue merely because existing tests pass.

When uncertain, identify the uncertainty and explain what experiment or source inspection would resolve it.

---

## No Unverified Claims

Never claim that:

- code compiles when it has not been compiled;
- tests pass when they have not been run;
- a kernel supports a feature without checking the relevant ABI/version;
- a syscall is blocked without testing or inspecting the filter;
- a filesystem restriction is enforced without accounting for Landlock behavior;
- a security property exists merely because documentation says it exists.

Distinguish:

```text
"the code appears to..."
```

from:

```text
"the test demonstrates..."
```

and from:

```text
"the running kernel reports..."
```

---

## When Tooling Is Unavailable

If Linux execution, compilation, or testing is unavailable:

- Continue with static analysis if useful.
- Do not pretend the code was verified.
- Clearly identify what remains unverified.
- Avoid speculative changes intended solely to anticipate compiler/test failures.

For the current refactor, Linux verification is a required milestone.

---

## Definition of Done

A change is not considered complete merely because the source looks correct.

For implementation changes, the normal definition of done is:

- [ ] Intended behavior is clearly understood.
- [ ] Security implications have been considered.
- [ ] Existing API semantics are preserved unless intentionally changed.
- [ ] Relevant tests exist or have been updated.
- [ ] Code builds on Linux.
- [ ] Relevant tests pass.
- [ ] Integrated tests pass when applicable.
- [ ] Documentation is accurate.
- [ ] The final diff contains no unrelated changes.

For security-sensitive changes, the standard is higher: the relevant security property should be demonstrated by tests or by a concrete, reviewable argument tied to the underlying Linux mechanism.

---

## Final Principle

**Do not optimize for making the code look finished. Optimize for knowing what the code actually does.**

Clumps4Linux sits at the boundary between userspace C code and Linux kernel security mechanisms. Correctness therefore depends on the interaction between the source, compiler, libc, libseccomp, Landlock, kernel version, architecture, process lifecycle, and security policy.

When those disagree, investigate the disagreement rather than hiding it.
