# Clumps-WIP
A very much work in progress single header implementation of pledge/unveil for Linux using seccomp-bpf and landlock with an integrated testing framework

# Clumps4Linux

**OpenBSD-style `pledge()` and `unveil()` semantics for Linux**

> ⚠️ **Work in progress.**
>
> Clumps4Linux is currently undergoing a substantial refactor. The current
> source has not yet been verified by a post-refactor Linux build and
> integrated test run. Do not treat the current WIP snapshot as a production
> security boundary.

Clumps4Linux is a single-header C library that combines Linux **seccomp-BPF**
and **Landlock LSM** to provide an API modeled on the security semantics of
OpenBSD's `pledge(2)` and `unveil(2)`.

The project is not a literal reimplementation of the OpenBSD kernel
interfaces. Linux and OpenBSD provide different security primitives, so some
semantics are necessarily approximated or implemented using different
mechanisms.

---

## Current Status

This repository is the public WIP repository for Clumps4Linux.

The current development priority is:

1. Build the current refactored source on Linux.
2. Resolve compilation and linker errors.
3. Run the integrated test harness.
4. Resolve test failures.
5. Establish a known-good Linux baseline.
6. Resume further development only after that baseline exists.

The source is intentionally frozen at this stage. Do not infer correctness
from successful static inspection on macOS or from the appearance of the
source alone.

---

## What It Provides

Clumps4Linux currently implements two complementary layers:

### `pledge()`-style restrictions

Pledge promises are translated primarily into **seccomp-BPF** syscall
restrictions.

The library supports promise groups covering areas such as:

- standard I/O;
- filesystem operations;
- process management;
- program execution;
- networking;
- UNIX-domain sockets;
- identity changes;
- file attributes;
- selected `ioctl` operations;
- `io_uring`;
- file-descriptor transfer.

### `unveil()`-style restrictions

Filesystem rules are implemented primarily using **Landlock**.

Paths supplied to `lunveil()` are canonicalized when the rule is created.
Landlock then provides the kernel-enforced filesystem access control after the
rules are locked.

Landlock is an allow-list mechanism. It cannot generally express every
possible OpenBSD `unveil()` semantic, particularly where an already-allowed
ancestor would need to contain an excluded descendant.

---

## Requirements

### Build environment

- Linux
- GCC 7.0+ or Clang 5.0+
- C11 with GNU extensions (`-std=gnu11`)
- libseccomp 2.4+
- pthreads
- Landlock support in the running kernel for filesystem restrictions

The project targets:

- x86_64
- aarch64
- riscv64

The authoritative build and test environment is Linux.

An amd64 Linux build does not by itself establish aarch64 or riscv64
compatibility.

### Kernel support

Landlock filesystem support begins with kernels providing Landlock ABI 1.

Additional Landlock functionality depends on the ABI exposed by the running
kernel. Clumps4Linux therefore performs runtime ABI detection rather than
assuming that the newest supported interface is available.

Use:

```c
int abi = clumps_get_landlock_abi();
```

to determine the ABI exposed by the running kernel.

A return value of `0` means that Landlock is unavailable to the process.

---

## Installation

Clumps4Linux is currently distributed as a single header.

Copy:

```text
clumps.h
```

into your project.

In exactly one translation unit, define `CLUMPS_IMPLEMENTATION` before
including the header:

```c
#define CLUMPS_IMPLEMENTATION
#include "clumps.h"
```

Other translation units should include the header normally:

```c
#include "clumps.h"
```

---

## Linking

A typical GCC build is:

```sh
gcc -O2 -Wall -Wextra -Werror=unused-result -std=gnu11 \
    main.c -o my_app -lseccomp -lpthread
```

Clang can be used similarly:

```sh
clang -O2 -Wall -Wextra -Werror=unused-result -std=gnu11 \
    main.c -o my_app -lseccomp -lpthread
```

`-std=gnu11` is intentional. The implementation uses GNU C extensions.

The project does not currently target:

- MSVC;
- Intel ICC;
- TenDRA C;
- strict ISO C mode with `-pedantic`.

---

## Quick Start

A minimal secured program can establish filesystem rules and then install
pledge restrictions:

```c
#define CLUMPS_IMPLEMENTATION
#include "clumps.h"

int main(void) {
    if (lunveil("/etc/ssl/certs", "r") != 0)
        return 1;

    if (lunveil("/tmp", "w") != 0)
        return 1;

    /*
     * Filesystem unveil rules must be finalized before installing a pledge
     * containing filesystem-related promises.
     */
    if (lunveil_lock() != 0)
        return 1;

    if (install_pledge("stdio rpath exec", "stdio") != 0)
        return 1;

    pid_t pid = fork();

    if (pid == 0) {
        /*
         * Contract the child before executing the worker.
         */
        if (install_pledge_exec("stdio") != 0)
            _exit(1);

        execl("./worker", "worker", NULL);
        _exit(1);
    }

    if (pid > 0)
        waitpid(pid, NULL, 0);

    return 0;
}
```

Always check return values from security-related operations. A failed
security operation must not be treated as equivalent to a successfully
installed restriction.

---

## Critical Lifecycle Rule

When filesystem-related promises are requested, the required order is:

```text
lunveil()
    ↓
lunveil_lock()
    ↓
install_pledge()
```

In particular, `lunveil_lock()` must be called before
`install_pledge()` when the pledge requires filesystem enforcement.

This applies to promises including:

- `rpath`
- `wpath`
- `cpath`
- `tmppath`
- `getpw`
- `exec` when filesystem execution restrictions are involved

Calling `install_pledge()` first can result in `EPERM`.

---

## Pledge API

### `install_pledge()`

```c
int install_pledge(const char *promises, const char *execpromises);
```

Installs the initial pledge policy.

`promises` specifies the permissions available to the current process.

`execpromises` specifies the permissions that may be used for a later
exec-transition and must be a subset of the effective promises.

A `NULL` `execpromises` value is permitted when no exec-transition contract is
configured.

The initial pledge is monotonic. Once restrictions have been installed, a
later call cannot expand the effective policy.

### `install_pledge_single()`

```c
int install_pledge_single(const char *promises);
```

Compatibility wrapper equivalent to calling `install_pledge()` with no
exec-promises.

### `install_pledge_exec()`

```c
int install_pledge_exec(const char *execpromises);
```

Installs a contracted child policy.

The intended pattern is:

```text
parent:
    install_pledge(promises, execpromises)

child:
    install_pledge_exec(execpromises)
    execve(...)
```

The child contract can only reduce the existing policy.

### `clump_execve()`

```c
int clump_execve(const char *path, char *const argv[], char *const envp[]);
```

Provides an exec wrapper that performs the configured child contraction before
calling `execve()`.

This can be used to avoid accidentally forgetting the explicit
`install_pledge_exec()` step.

---

## Unveil API

### `lunveil()`

```c
int lunveil(const char *path, const char *perms);
```

Adds a filesystem access rule.

Paths are canonicalized when the rule is created.

Repeated rules do not expand previously granted permissions; permissions are
intersected.

The exact semantics depend on the Landlock capabilities available from the
running kernel.

### `lunveil_net()`

```c
int lunveil_net(uint64_t port, const char *perms);
```

Adds a network port rule where the running kernel provides the required
Landlock network ABI.

Network support is kernel-dependent.

The implementation currently requires Landlock ABI 4 or later for network
rules. Port `0` has additional ABI requirements.

### `lunveil_lock()`

```c
int lunveil_lock(void);
```

Finalizes the accumulated unveil policy and installs the Landlock restriction.

Equivalent to:

```c
lunveil_lock_ext(0);
```

### `lunveil_lock_ext()`

```c
int lunveil_lock_ext(uint32_t flags);
```

Finalizes the unveil policy with optional behavior flags, including graceful
fallback where supported.

---

## Promise Tokens

The current pledge parser recognizes:

| Token | General purpose |
|---|---|
| `stdio` | Standard I/O and selected descriptor/event operations |
| `rpath` | Read-oriented filesystem operations |
| `wpath` | Write-oriented filesystem operations |
| `cpath` | Filesystem creation/removal/rename operations |
| `tmppath` | Temporary-file creation support |
| `getpw` | Password/group database access |
| `inet` | IPv4/IPv6 networking |
| `dns` | DNS-oriented networking |
| `unix` | UNIX-domain sockets |
| `exec` | Program execution |
| `proc` | Process management |
| `id` | Identity changes |
| `ioctl` | Unconditional `ioctl` access |
| `tty` | Terminal-specific operations |
| `io_uring` | `io_uring` operations |
| `fattr` | File attribute changes |
| `recvfd` | Receiving file descriptors |
| `sendfd` | Sending file descriptors |

These tokens describe Clumps4Linux policy groups. They should not be assumed
to have byte-for-byte identical semantics to OpenBSD pledge promises.

---

## Important Promise Interactions

### `ioctl` and `stdio`

The `ioctl` promise allows the `ioctl` syscall unconditionally.

Consequently, it supersedes the narrower ioctl rules used by `stdio`.

If only the narrower terminal-related ioctl behavior is required, use the
more specific promise instead of `ioctl`.

### `getpw`

At the seccomp layer, `getpw` is closely related to read-path access.

Actual filesystem access remains subject to Landlock when Landlock is active.

### `tty`

The `tty` promise permits the relevant terminal operations at the seccomp
layer. Landlock can still prevent access to the actual device path.

---

## Exec-Promise Contraction

The exec-promise mechanism is intended to model the OpenBSD pattern where a
process can delegate a smaller set of permissions to a child.

Example:

```c
if (install_pledge("stdio rpath exec", "stdio") != 0)
    return 1;

pid_t pid = fork();

if (pid == 0) {
    if (install_pledge_exec("stdio") != 0)
        _exit(1);

    execl("./worker", "worker", NULL);
    _exit(1);
}

waitpid(pid, NULL, 0);
```

Seccomp filters are inherited across `fork()` and are additive. A contracted
child therefore cannot regain permissions removed by an earlier filter.

If a descendant creates another child, do not assume that the descendant has
automatically received a new, narrower contract merely because an ancestor
was contracted.

Where appropriate, explicitly re-contract descendants.

---

## Seccomp Fail Actions

The default seccomp failure action is process termination.

Debug/configuration flags can select different failure behavior, including
`SCMP_ACT_ERRNO(EPERM)` and logging behavior.

The child contraction mechanism preserves the configured fail-action policy
of the parent pledge rather than silently changing it.

This distinction matters when diagnosing tests or developing applications.

---

## Landlock ABI Detection

Landlock functionality is detected at runtime.

The library caches the detected ABI and adjusts the ruleset it constructs to
the capabilities actually available from that ABI.

For example:

```c
int abi = clumps_get_landlock_abi();

if (abi < 4) {
    fprintf(stderr,
            "Landlock network restrictions are unavailable\n");
}
```

Do not assume that a kernel version, compiler version, or libc version alone
proves that a particular Landlock feature is available.

---

## Graceful Fallback

If Landlock is unavailable, filesystem restrictions cannot be reproduced by
seccomp alone.

The library provides a graceful-fallback mode that can allow the process to
continue with the restrictions that Linux can enforce without Landlock.

For example:

```c
if (lunveil_lock_ext(CLUMPS_GRACEFUL_FALLBACK) != 0) {
    perror("lunveil_lock_ext");
    return 1;
}
```

Graceful fallback should **not** be interpreted as equivalent to full
filesystem confinement.

Seccomp filters restrict syscalls and syscall arguments; they do not provide
general pathname-based access control.

Applications that require the filesystem restrictions should treat missing
Landlock support as a configuration failure rather than silently accepting
the fallback.

---

## W^X Protection

Where implemented by the selected pledge policy, Clumps4Linux restricts
memory mapping/protection operations so that writable and executable
permissions cannot be requested simultaneously through the guarded
operations.

This is implemented through conditional seccomp rules on relevant syscall
arguments.

This is **not a complete memory-integrity guarantee**.

Known limitations include operations such as `brk()` and `mremap()` that are
not completely covered by the current implementation.

Do not describe the current W^X implementation as a complete substitute for
a comprehensive memory-hardening strategy.

---

## Threading

The default pledge installation mode uses seccomp thread synchronization.

Security policy should therefore be established early in process startup,
before creating application threads.

The library also provides a per-thread mode where supported by the API.

Applications using threads should explicitly understand whether the selected
mode is process-wide or thread-specific before installing a policy.

---

## Error Handling

The public security APIs return `0` on success and `-1` on failure.

On failure, `errno` is set appropriately.

The library also maintains error context accessible through:

```c
clumps_error_ctx_t clumps_get_last_error(void);
```

Security-related return values should always be checked.

In particular, do not ignore failures from:

```c
lunveil()
lunveil_net()
lunveil_lock()
lunveil_lock_ext()
install_pledge()
install_pledge_exec()
clump_execve()
clumps_close_extra_fds()
clumps_set_resource_limits()
```

---

## Additional Helpers

### `clumps_close_extra_fds()`

```c
int clumps_close_extra_fds(int min_fd);
```

Closes file descriptors above the specified minimum, helping reduce
accidental descriptor inheritance.

### `clumps_set_resource_limits()`

```c
int clumps_set_resource_limits(...);
```

Provides resource-limit support for file descriptors and processes.

Resource exhaustion is not prevented merely by installing pledge/unveil
restrictions. Applications requiring resource-exhaustion protection should
configure appropriate `RLIMIT_*` values or use other resource controls.

### `clumps_get_landlock_abi()`

```c
int clumps_get_landlock_abi(void);
```

Returns the detected Landlock ABI, or `0` when Landlock is unavailable.

### `clumps_version()`

```c
const char *clumps_version(void);
```

Returns the library version string.

---

## Testing

The integrated test harness is compiled directly from the single header:

```sh
gcc -O2 -Wall -Wextra -Werror=unused-result -std=gnu11 \
    -DCLUMPS_TESTS clumps.h -o clumps_test \
    -lseccomp -lpthread
```

Run:

```sh
./clumps_test
```

Tests use isolated child processes where necessary because seccomp state is
monotonic and cannot simply be removed from a process after installation.

For reproducible parametric test runs, set:

```sh
export CLUMPS_PB_SEED=12345
```

before running the test harness.

Do not weaken security tests merely to obtain a passing test run.

---

## Security Model

Clumps4Linux is intended to reduce the kernel-visible capabilities of a
process by combining independent Linux mechanisms.

Conceptually:

```text
                  Application
                       │
              ┌────────┴────────┐
              │                 │
         pledge policy      unveil policy
              │                 │
          seccomp-BPF        Landlock
              │                 │
              └────────┬────────┘
                       │
                 Linux kernel
```

Neither layer should be considered interchangeable with the other.

Seccomp is primarily concerned with **which syscalls and syscall arguments
the process may use**.

Landlock is primarily concerned with **which filesystem and supported network
resources the process may access**.

The security boundary therefore depends on both layers being installed
successfully and on the running kernel providing the capabilities required
by the requested policy.

---

## Known Limitations

Clumps4Linux intentionally documents several limitations.

### Path canonicalization

Paths are canonicalized at unveil time.

This introduces a TOCTOU window between pathname resolution and subsequent
kernel enforcement.

### Landlock allow-list semantics

Landlock cannot generally express "allow this directory but deny this
subtree" when the ancestor has already been granted equivalent access.

### Network restrictions

Network restrictions depend on the Landlock ABI supported by the running
kernel.

The current implementation covers supported bind/connect operations for the
network protocols exposed by the available Landlock ABI.

It does not provide general raw-network or ICMP confinement.

### Descendant processes

Seccomp filters are inherited and additive, but an ancestor's exec contract
does not automatically establish a new contract for every future descendant.

Applications launching untrusted descendant processes should explicitly
consider process and namespace isolation.

### Resource exhaustion

Pledge/unveil restrictions do not by themselves prevent denial of service
through resource exhaustion.

Use resource limits, cgroups, namespaces, or other appropriate mechanisms
where required.

### Namespace isolation

Clumps4Linux is not a namespace sandbox.

Applications requiring isolation from process IDs, mounts, users, networks,
or other kernel namespaces should use the corresponding Linux namespace
mechanisms.

### W^X

The current W^X implementation is limited to the operations covered by its
seccomp rules. It is not a comprehensive memory-hardening mechanism.

### `ioctl`

The `ioctl` promise intentionally provides broad access to the syscall.

Applications requiring narrower ioctl access should use a more specific
policy where available.

---

## What Clumps4Linux Is Not

Clumps4Linux is not:

- a container runtime;
- a complete Linux sandbox;
- a replacement for SELinux or AppArmor;
- a replacement for namespaces or cgroups;
- a complete reproduction of OpenBSD's kernel security model;
- protection against kernel vulnerabilities;
- a guarantee that an application is free of security vulnerabilities.

It is a userspace library for constructing a narrower process security policy
using Linux kernel facilities.

For stronger isolation, Clumps4Linux can be combined with other Linux
security mechanisms.

---

## Recommended Defense in Depth

Depending on the application, consider combining Clumps4Linux with:

- seccomp user notification for advanced policy decisions;
- SELinux or AppArmor for mandatory access control;
- namespaces for process, mount, user, network, and other isolation;
- cgroups for resource control;
- `setrlimit()` / `RLIMIT_*` for per-process resource limits;
- appropriate filesystem ownership and permissions.

No individual mechanism should be assumed to provide every required security
property.

---

## Development

The project is deliberately kept as a single-header library.

The implementation is enabled with:

```c
#define CLUMPS_IMPLEMENTATION
#include "clumps.h"
```

The test harness is enabled with:

```c
#define CLUMPS_TESTS
#include "clumps.h"
```

During development, use:

```text
-Wall
-Wextra
-Werror=unused-result
-std=gnu11
```

The repository also contains `AGENTS.md`, which defines the project's
development and review expectations, particularly around preserving security
semantics and avoiding unrelated refactoring.

---

## Versioning

The current source identifies itself through:

```c
clumps_version()
```

The repository is currently a WIP snapshot rather than a production release.

Version numbers should not be interpreted as a security or compatibility
guarantee until the corresponding release has been built and tested on the
supported Linux environments.

---

## Contributing

Before making a change:

1. Read `AGENTS.md`.
2. Understand the relevant security mechanism.
3. Search for existing callers and tests.
4. Make the smallest change that addresses the task.
5. Build on Linux.
6. Run the relevant tests.
7. Run the integrated test harness.
8. Inspect the final diff.

Do not change test expectations merely to make tests pass.

Do not claim that code compiles or tests pass unless the relevant commands
were actually run.

Security-sensitive changes should include tests or a concrete, reviewable
argument explaining the resulting kernel behavior.

---

## Project

Current public WIP repository:

https://github.com/Clumps4Linux/Clumps-WIP/

The project is MIT licensed.

---

## License

MIT License.

See [`LICENSE`](LICENSE) for the complete license text.

---

## Disclaimer

Clumps4Linux is experimental security software.

The current WIP source has not yet completed post-refactor Linux
verification. Even after the current test suite passes, successful tests will
not establish that the library provides a complete or vulnerability-free
security boundary.

Review the implementation, understand the underlying Linux security
mechanisms, and test the resulting application in its actual deployment
environment before relying on Clumps4Linux for security isolation.
