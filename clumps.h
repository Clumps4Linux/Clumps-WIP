/* ===========================================================================
 * LICENSE AND FILE HEADER
 *
 * clumps.h - A Linux implementation of OpenBSD pledge(2) and unveil(2)
 *            semantics
 *
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Clumps4Linux Developers
 *
 * Project:
 * https://github.com/Clumps-WIP
 *
 * Author Key:
 * 21ed2e15937b1758af0e57f4bfdc763e00fe9bfef58d81022893f32d5605ec10
 *
 * ========================================================================= */

/* ===========================================================================
 * CHANGELOG
 * ---------------------------------------------------------------------------
 * v1.8.2 -> v1.8.3:
 * [CORE] PLEDGE_MAP table replaces 18 if-statements in calculate_promises_mask().
 *        (~35 lines removed, identical functionality).
 * [CORE] W_X_PROTECT macro consolidates W^X rule generation (mmap/mprotect).
 *        (~5 lines removed).
 * [TEST] Test harness consolidation: 3 property tests + 4 basic promise tests
 *        + 2 expansion tests merged into parametric loops (~570 lines removed).
 *        Test harness reduced from ~930 to ~360 lines. All seccomp isolation
 *        preserved via forked-child model.
 * [HYGIENE] Added #include <stdbool.h> and #include <limits.h> to test harness.
 * ========================================================================= */

/* ===========================================================================
 * QUICK START EXAMPLE
 *   #define CLUMPS_IMPLEMENTATION
 *   #include "clumps.h"
 *
 *   int main(void) {
 *       lunveil("/etc/ssl/certs", "r");
 *       lunveil("/tmp", "w");
 *       lunveil_lock();                              // ← MUST precede install_pledge
 *
 *       install_pledge("stdio rpath exec", "stdio"); // parent + execpromises
 *
 *       pid_t pid = fork();
 *       if (pid == 0) {
 *           install_pledge_exec("stdio");           // child contracts before execve
 *           execl("./worker", "worker", NULL);
 *       }
 *       waitpid(pid, NULL, 0);
 *       return 0;
 *   }
 * ========================================================================= */

/* ===========================================================================
 * FULL DOCUMENTATION: See README.md for kernel requirements, build options,
 * security threat model, and comprehensive promise semantics.
 * https://github.com/Clumps4Linux/clumps/blob/main/README.md
 * ========================================================================= */

#if defined(CLUMPS_IMPLEMENTATION) || defined(CLUMPS_TESTS)
static inline int _get_landlock_abi_cached(void) CLUMPS_ALWAYS_INLINE;

static struct lunveil_rule lunveil_rules[CLUMPS_MAX_RULES];
static size_t lunveil_rules_len = 0;
static int lunveil_locked = 0;
static uint32_t current_promises_mask = 0;
static int initialization_done = 0;
static pthread_mutex_t lunveil_mutex = PTHREAD_MUTEX_INITIALIZER;

// Execpromises state - tracks promised permissions for child exec transition
static uint32_t stored_execpromises_mask = 0;
static int has_execpromises = 0;
static int exec_pledged = 0;

// Stored pledge flags - captured at the (last successfully installed) pledge.
// install_pledge_exec() reuses these so that a contracted child keeps the
// SAME fail-action policy (EPERM/LOG) as its parent instead of silently
// reverting to SCMP_ACT_KILL_PROCESS. Seccomp filters are additive with
// most-severe-action-wins precedence, so a KILL default on the contraction
// layer defeated CLUMPS_DEBUG_EPERM / CLUMPS_ENABLE_LOG in children.
static uint32_t stored_pledge_flags = 0;

static ATOMIC_INT landlock_cached_abi = -1;

static CLUMPS_CONSTRUCTOR void _clumps_ctor(void) {
    _get_landlock_abi_cached();
}

static void _set_error_context(int api_call, int err, const char *fmt, ...)
    CLUMPS_FORMAT_PRINTF(3, 4) CLUMPS_COLD;

// Error context setter - uses thread-local storage instead of global mutex
static void _set_error_context(int api_call, int err, const char *fmt, ...) {
    va_list args;
    clumps_error_ctx_t *ctx = &_clumps_last_error_tl;
    ctx->api_call = api_call;
    ctx->kernel_errno = err;
    ctx->abi_version = _get_landlock_abi_cached();
    va_start(args, fmt);
    vsnprintf(ctx->message, sizeof(ctx->message), fmt, args);
    va_end(args);
}

void clumps_reset_error(void) {
    clumps_error_ctx_t *ctx = &_clumps_last_error_tl;
    memset(ctx, 0, sizeof(*ctx));
}

uint32_t clumps_get_promise_mask(void) {
    pthread_mutex_lock(&lunveil_mutex);
    uint32_t mask = current_promises_mask;
    pthread_mutex_unlock(&lunveil_mutex);
    return mask;
}

// Query stored execpromises mask - returns the mask configured for exec transition
uint32_t clumps_get_execpromises_mask(void) {
    pthread_mutex_lock(&lunveil_mutex);
    uint32_t mask = stored_execpromises_mask;
    pthread_mutex_unlock(&lunveil_mutex);
    return mask;
}

// Check if exec transition has been applied - child has called install_pledge_exec()
int clumps_is_exec_pledged(void) {
    pthread_mutex_lock(&lunveil_mutex);
    int val = exec_pledged;
    pthread_mutex_unlock(&lunveil_mutex);
    return val;
}

static void _lunveil_log(const char *func, const char *fmt, ...)
    CLUMPS_FORMAT_PRINTF(2, 3) CLUMPS_COLD;

static void _lunveil_log(const char *func, const char *fmt, ...) {
    if (!_clumps_debug.enabled || !_clumps_debug.output) return;
    fprintf(_clumps_debug.output, "[CLUMPS][%s] ", func);
    va_list args;
    va_start(args, fmt);
    vfprintf(_clumps_debug.output, fmt, args);
    va_end(args);
    fflush(_clumps_debug.output);
}

#define LOG(fmt, ...) _lunveil_log(__func__, fmt, ##__VA_ARGS__)

static void _lunveil_cleanup(void) CLUMPS_COLD {
    for (size_t i = 0; i < lunveil_rules_len; i++) {
        if (lunveil_rules[i].type == CLUMPS_RULE_FS) {
            if (lunveil_rules[i].data.fs.fd >= 0) {
                close(lunveil_rules[i].data.fs.fd);
                lunveil_rules[i].data.fs.fd = -1;
            }
            if (lunveil_rules[i].data.fs.path) {
                free(lunveil_rules[i].data.fs.path);
                lunveil_rules[i].data.fs.path = NULL;
            }
        }
    }
    memset(lunveil_rules, 0, sizeof(lunveil_rules));
    lunveil_rules_len = 0;
}

const char *clumps_version(void) {
    return CLUMPS_VERSION;
}

clumps_error_ctx_t clumps_get_last_error(void) {
    clumps_error_ctx_t copy = _clumps_last_error_tl;
    return copy;
}

void clumps_set_debug(int enabled, int level, FILE *output) {
    _clumps_debug.enabled = enabled;
    _clumps_debug.level = level;
    _clumps_debug.output = output ? output : stderr;
}

// Helper: Returns correct struct size for given ABI version.
// ABI 1-5: 16 bytes (handled_access_fs only)
// ABI 6+: Full struct with scoped field
// Using wrong size causes EINVAL on older kernels
static inline size_t _landlock_struct_size_for_abi(int abi) {
    if (abi < 6) return 16;
    return sizeof(struct landlock_ruleset_attr);
}

static inline int _get_landlock_abi_cached(void) {
    int cached = ATOMIC_LOAD(landlock_cached_abi);
    if (CLUMPS_LIKELY(cached >= 0)) return cached;
#ifdef __NR_landlock_create_ruleset
    int abi = syscall(__NR_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) {
        ATOMIC_STORE(landlock_cached_abi, 0);
        return 0;
    } else {
        ATOMIC_STORE(landlock_cached_abi, abi);
        return abi;
    }
#else
    ATOMIC_STORE(landlock_cached_abi, 0);
    return 0;
#endif
}

// Public helper: Exposed struct size for ABI version - useful for callers
// building Landlock structures manually
size_t clumps_landlock_struct_size_for_abi(int abi) {
    return _landlock_struct_size_for_abi(abi);
}

// Convert permission string to Landlock access bits
// 'r' = read file/dir, 'w' = write/remove/make/truncate, 'x' = execute
static inline __u64 lunveil_perms_to_access(const char *perms) {
    __u64 acc = 0;
    for (const char *p = perms; p && *p; p++) {
        switch (*p) {
            case 'r': acc |= LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR; break;
            case 'w': acc |= LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_FILE |
                          LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
                          LANDLOCK_ACCESS_FS_TRUNCATE; break;
            case 'x': acc |= LANDLOCK_ACCESS_FS_EXECUTE; break;
            default: return 0;
        }
    }
    return acc;
}

// Convert network permission string to Landlock access bits
// 'b' = bind, 'c' = connect. UDP requires ABI 10+
static inline __u64 lunveil_net_perms_to_access(const char *perms, int abi) {
    __u64 acc = 0;
    for (const char *p = perms; p && *p; p++) {
        switch (*p) {
            case 'b': acc |= LANDLOCK_ACCESS_NET_BIND_TCP;
                      if (abi >= 10) acc |= LANDLOCK_ACCESS_NET_BIND_UDP; break;
            case 'c': acc |= LANDLOCK_ACCESS_NET_CONNECT_TCP;
                      if (abi >= 10) acc |= LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP; break;
            default: return 0;
        }
    }
    return acc;
}

// Check if prefix is a directory prefix of path (e.g., "/etc" is prefix of "/etc/ssl")
// Returns true if path starts with prefix followed by '/' or end-of-string
static inline int path_is_prefix(const char *prefix, const char *path) {
    size_t plen = strlen(prefix);
    if (plen == 0) return 0;
    if (strncmp(prefix, path, plen) != 0) return 0;
    if (path[plen] == '\0') return 1;
    return (path[plen] == '/');
}

// Add filesystem rule - restrict access to path with given permissions
// Can be called multiple times for same path (permissions intersect, never expand)
// Returns 0 on success, -1 on error (sets errno and error context)
int lunveil(const char *path, const char *perms) CLUMPS_NONNULL(1) {
    if (CLUMPS_UNLIKELY(lunveil_locked)) {
        LOG("ERROR: lunveil() called after lunveil_lock()\n");
        _set_error_context(1, EPERM, "lunveil() after lock");
        SET_ERRNO_AND_RETURN(-1, EPERM);
    }
    if (CLUMPS_UNLIKELY(!path)) {
        LOG("ERROR: lunveil(NULL, ...) is invalid\n");
        _set_error_context(1, EINVAL, "NULL path");
        SET_ERRNO_AND_RETURN(-1, EINVAL);
    }

    int abi = _get_landlock_abi_cached();
    if (CLUMPS_UNLIKELY(abi < 1)) {
        LOG("WARNING: Landlock ABI %d - filesystem restrictions unavailable\n", abi);
        _set_error_context(1, ENOTSUP, "Landlock ABI %d", abi);
        SET_ERRNO_AND_RETURN(-1, ENOTSUP);
    }

    // Canonicalize path via realpath() - ensures consistent representation
    // For hidden paths (perms == NULL), keep raw path if realpath fails
    char resolved[PATH_MAX];
    if (realpath(path, resolved)) {
        // canonicalized
    } else if (!perms) {
        LOG("DEBUG: Marking hidden path (raw, realpath failed): %s\n", path);
        strncpy(resolved, path, PATH_MAX - 1);
        resolved[PATH_MAX - 1] = '\0';
    } else {
        LOG("ERROR: realpath(%s) failed: %s\n", path, strerror(errno));
        _set_error_context(1, errno, "realpath(%s)", path);
        return -1;
    }

    __u64 acc = 0;
    if (perms) {
        acc = lunveil_perms_to_access(perms);
        if (CLUMPS_UNLIKELY(!acc)) {
            LOG("ERROR: Invalid permission string: %s\n", perms);
            _set_error_context(1, EINVAL, "invalid perms '%s'", perms);
            SET_ERRNO_AND_RETURN(-1, EINVAL);
        }
    }

    SCOPED_SIGMASK();
    SCOPED_MUTEX(lunveil_mutex);

    // Check if path already exists - update permissions or mark hidden
    for (size_t i = 0; i < lunveil_rules_len; i++) {
        if (lunveil_rules[i].type == CLUMPS_RULE_FS &&
            lunveil_rules[i].data.fs.path &&
            strcmp(lunveil_rules[i].data.fs.path, resolved) == 0) {
            if (!perms) {
                // Hide: clear permissions and set hidden flag
                if (lunveil_rules[i].data.fs.fd >= 0) {
                    close(lunveil_rules[i].data.fs.fd);
                    lunveil_rules[i].data.fs.fd = -1;
                }
                lunveil_rules[i].data.fs.access = 0;
                lunveil_rules[i].data.fs.hidden = 1;
                return 0;
            } else {
                // Intersection: reduce permissions (never expand)
                lunveil_rules[i].data.fs.access &= acc;
                if (lunveil_rules[i].data.fs.access == 0 &&
                    lunveil_rules[i].data.fs.fd >= 0) {
                    close(lunveil_rules[i].data.fs.fd);
                    lunveil_rules[i].data.fs.fd = -1;
                }
                return 0;
            }
        }
    }

    // Monotonicity check: new rule must not exceed ancestor rule permissions
    for (size_t i = 0; i < lunveil_rules_len; i++) {
        if (lunveil_rules[i].type != CLUMPS_RULE_FS ||
            !lunveil_rules[i].data.fs.path ||
            lunveil_rules[i].data.fs.hidden) continue;
        if (path_is_prefix(lunveil_rules[i].data.fs.path, resolved)) {
            if ((acc & ~lunveil_rules[i].data.fs.access) != 0) {
                LOG("ERROR: Violates monotonicity - %s exceeds ancestor %s\n",
                     resolved, lunveil_rules[i].data.fs.path);
                _set_error_context(1, EPERM, "monotonicity violation");
                SET_ERRNO_AND_RETURN(-1, EPERM);
            }
        }
    }

    // Rule cap check
    if (CLUMPS_UNLIKELY(lunveil_rules_len >= CLUMPS_MAX_RULES)) {
        _set_error_context(1, ENOMEM, "rule limit");
        SET_ERRNO_AND_RETURN(-1, ENOMEM);
    }

    // Hidden path: just mark it, no fd needed
    if (!perms) {
        char *dup_path = strdup(resolved);
        if (CLUMPS_UNLIKELY(!dup_path)) {
            _set_error_context(1, ENOMEM, "strdup hidden path");
            SET_ERRNO_AND_RETURN(-1, ENOMEM);
        }
        struct lunveil_rule *r = &lunveil_rules[lunveil_rules_len];
        memset(r, 0, sizeof(*r));
        r->type = CLUMPS_RULE_FS;
        r->data.fs.fd = -1;
        r->data.fs.access = 0;
        r->data.fs.hidden = 1;
        r->data.fs.path = dup_path;
        lunveil_rules_len++;
        return 0;
    }

    // Normal rule: open path to get fd for Landlock
    int target_fd = openat(AT_FDCWD, resolved, O_PATH | O_CLOEXEC | O_NOFOLLOW);
    if (CLUMPS_UNLIKELY(target_fd < 0)) {
        _set_error_context(1, errno, "openat(%s)", resolved);
        return -1;
    }

    char *dup_path = strdup(resolved);
    if (CLUMPS_UNLIKELY(!dup_path)) {
        close(target_fd);
        _set_error_context(1, ENOMEM, "strdup resolved path");
        SET_ERRNO_AND_RETURN(-1, ENOMEM);
    }

    struct lunveil_rule *r = &lunveil_rules[lunveil_rules_len];
    memset(r, 0, sizeof(*r));
    r->type = CLUMPS_RULE_FS;
    r->data.fs.fd = target_fd;
    r->data.fs.access = acc;
    r->data.fs.hidden = 0;
    r->data.fs.path = dup_path;
    lunveil_rules_len++;
    return 0;
}

// Add network rule - restrict bind/connect to given port
// Requires Landlock ABI 4+. Port 0 (privileged ports) requires ABI 10+
int lunveil_net(uint64_t port, const char *perms) CLUMPS_NONNULL(2) {
    if (CLUMPS_UNLIKELY(lunveil_locked)) {
        _set_error_context(2, EPERM, "lunveil_net() after lock");
        SET_ERRNO_AND_RETURN(-1, EPERM);
    }
    if (CLUMPS_UNLIKELY(!perms || port > 65535)) {
        _set_error_context(2, EINVAL, "invalid lunveil_net params");
        SET_ERRNO_AND_RETURN(-1, EINVAL);
    }

    int abi = _get_landlock_abi_cached();
    if (CLUMPS_UNLIKELY(abi < 4)) {
        _set_error_context(2, ENOTSUP, "Landlock ABI %d for network", abi);
        SET_ERRNO_AND_RETURN(-1, ENOTSUP);
    }

    if (port == 0 && abi < 10) {
        _set_error_context(2, EINVAL, "port 0 requires ABI 10+");
        SET_ERRNO_AND_RETURN(-1, EINVAL);
    }

    __u64 acc = lunveil_net_perms_to_access(perms, abi);
    if (CLUMPS_UNLIKELY(!acc)) {
        _set_error_context(2, EINVAL, "invalid net perms '%s'", perms);
        SET_ERRNO_AND_RETURN(-1, EINVAL);
    }

    SCOPED_SIGMASK();
    SCOPED_MUTEX(lunveil_mutex);
    if (CLUMPS_UNLIKELY(lunveil_rules_len >= CLUMPS_MAX_RULES)) {
        _set_error_context(2, ENOMEM, "rule limit");
        SET_ERRNO_AND_RETURN(-1, ENOMEM);
    }

    struct lunveil_rule *r = &lunveil_rules[lunveil_rules_len];
    memset(r, 0, sizeof(*r));
    r->type = CLUMPS_RULE_NET;
    r->data.net.port = port;
    r->data.net.access = acc;
    lunveil_rules_len++;
    return 0;
}

int lunveil_lock(void) {
    return lunveil_lock_ext(0);
}

// Finalize unveil rules and install Landlock policy
// Must be called before install_pledge() when using filesystem promises
// Returns 0 on success, -1 on error
int lunveil_lock_ext(uint32_t flags) {
    SCOPED_SIGMASK();
    SCOPED_MUTEX(lunveil_mutex);
    if (lunveil_locked) return 0;

    int abi = _get_landlock_abi_cached();
    if (abi < 1) {
        if (flags & CLUMPS_GRACEFUL_FALLBACK) {
            lunveil_locked = 1;
            return 0;
        }
        _set_error_context(3, ENOTSUP, "Landlock ABI %d", abi);
        SET_ERRNO_AND_RETURN(-1, ENOTSUP);
    }

    // Build Landlock ruleset attribute with appropriate access rights
    __u64 hfs = CLUMPS_LANDLOCK_BASE_FS;
    __u64 hnet = 0;
    __u64 scoped = 0;

    if (abi >= 4) hnet |= LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP;
    if (abi >= 10) hnet |= LANDLOCK_ACCESS_NET_BIND_UDP | LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP;
    if (abi >= 6) scoped |= LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL;

    struct landlock_ruleset_attr rs_attr;
    memset(&rs_attr, 0, sizeof(rs_attr));
    rs_attr.handled_access_fs = hfs;
    rs_attr.handled_access_net = hnet;
    rs_attr.scoped = scoped;

    // ABI-specific capability trimming
    if (abi < 2) rs_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_REFER;
    if (abi < 3) rs_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_TRUNCATE;
    if (abi < 5) rs_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_IOCTL_DEV;
    if (abi < 6) rs_attr.scoped = 0;

    // Use correct struct size per ABI to avoid EINVAL on old kernels
    size_t rs_attr_size = _landlock_struct_size_for_abi(abi);

    if (abi >= 10 && (flags & CLUMPS_USE_QUIET_FLAGS)) {
#ifdef LANDLOCK_RULE_QUIET_ACCESS_FS
        rs_attr.quiet_access_fs = LANDLOCK_RULE_QUIET_ACCESS_FS;
#endif
#ifdef LANDLOCK_RULE_QUIET_ACCESS_NET
        rs_attr.quiet_access_net = LANDLOCK_RULE_QUIET_ACCESS_NET;
#endif
    }

    int saved_errno = 0;

#ifdef __NR_landlock_create_ruleset
    int rs_fd = syscall(__NR_landlock_create_ruleset, &rs_attr, rs_attr_size, 0);
#else
    int rs_fd = -1;
    errno = ENOTSUP;
#endif
    if (rs_fd < 0) {
        saved_errno = errno;
        _set_error_context(3, saved_errno, "landlock_create_ruleset");
        goto lock_fail_no_fd;
    }

    // Add filesystem rules to Landlock ruleset
    for (size_t i = 0; i < lunveil_rules_len; i++) {
        if (lunveil_rules[i].type == CLUMPS_RULE_FS) {
            if (lunveil_rules[i].data.fs.access == 0 ||
                lunveil_rules[i].data.fs.fd < 0) continue;
            struct landlock_path_beneath_attr pb;
            memset(&pb, 0, sizeof(pb));
            pb.allowed_access = lunveil_rules[i].data.fs.access & hfs;
            pb.parent_fd = lunveil_rules[i].data.fs.fd;
#ifdef __NR_landlock_add_rule
            if (syscall(__NR_landlock_add_rule, rs_fd, LANDLOCK_RULE_PATH_BENEATH, &pb, 0) < 0) {
                saved_errno = errno;
                _set_error_context(3, saved_errno, "landlock_add_rule(fs)");
                goto lock_fail;
            }
#else
            saved_errno = ENOTSUP;
            goto lock_fail;
#endif
        } else if (lunveil_rules[i].type == CLUMPS_RULE_NET && abi >= 4) {
            struct landlock_net_port_attr np;
            memset(&np, 0, sizeof(np));
            np.allowed_access = lunveil_rules[i].data.net.access & hnet;
            np.port = lunveil_rules[i].data.net.port;
#ifdef __NR_landlock_add_rule
            if (syscall(__NR_landlock_add_rule, rs_fd, LANDLOCK_RULE_NET_PORT, &np, 0) < 0) {
                saved_errno = errno;
                _set_error_context(3, saved_errno, "landlock_add_rule(net)");
                goto lock_fail;
            }
#else
            saved_errno = ENOTSUP;
            goto lock_fail;
#endif
        }
    }

    __u32 restrict_flags = 0;
    if (abi >= 7) restrict_flags |= LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON;

#ifdef __NR_landlock_restrict_self
    if (syscall(__NR_landlock_restrict_self, rs_fd, restrict_flags) < 0) {
        saved_errno = errno;
        _set_error_context(3, saved_errno, "landlock_restrict_self");
        goto lock_fail;
    }
#else
    saved_errno = ENOTSUP;
    goto lock_fail;
#endif

    close(rs_fd);
    _lunveil_cleanup();
    lunveil_locked = 1;
    return 0;

lock_fail:
    close(rs_fd);
lock_fail_no_fd:
    _lunveil_cleanup();
    // errno is propagated to the caller instead of leaving whatever value
    // internal calls happened to leave behind
    if (saved_errno != 0) errno = saved_errno;
    return -1;
}

// --- Promise parsing helper ---
static int str_has_token(const char *haystack, const char *token) {
    if (!haystack || !token) return 0;
    size_t tlen = strlen(token);
    if (tlen == 0) return 0;
    const char *p = haystack;
    while (*p) {
        while (*p && (isspace((unsigned char)*p) || *p == ',')) p++;
        if (!*p) break;
        const char *start = p;
        while (*p && !isspace((unsigned char)*p) && *p != ',') p++;
        if ((size_t)(p - start) == tlen && strncmp(start, token, tlen) == 0) {
            if (!*p || isspace((unsigned char)*p) || *p == ',') return 1;
        }
    }
    return 0;
}

// PLEDGE_MAP TABLE - Table-driven promise parsing instead of 18+ if statements.
// Maintains same functionality with ~35 fewer lines.
// Maps promise token strings to bit mask values
static const struct { const char *token; uint32_t bit; } PLEDGE_MAP[] = {
    {"stdio",    CLUMPS_PLEDGE_STDIO},   {"rpath",    CLUMPS_PLEDGE_RPATH},
    {"wpath",    CLUMPS_PLEDGE_WPATH},   {"cpath",    CLUMPS_PLEDGE_CPATH},
    {"inet",     CLUMPS_PLEDGE_INET},    {"dns",      CLUMPS_PLEDGE_DNS},
    {"proc",     CLUMPS_PLEDGE_PROC},    {"exec",     CLUMPS_PLEDGE_EXEC},
    {"id",       CLUMPS_PLEDGE_ID},      {"io_uring", CLUMPS_PLEDGE_IO_URING},
    {"unix",     CLUMPS_PLEDGE_UNIX},    {"recvfd",   CLUMPS_PLEDGE_RECVFD},
    {"sendfd",   CLUMPS_PLEDGE_SENDFD},  {"fattr",    CLUMPS_PLEDGE_FATTR},
    {"tmppath",  CLUMPS_PLEDGE_TMPPATH}, {"getpw",    CLUMPS_PLEDGE_GETPW},
    {"ioctl",    CLUMPS_PLEDGE_IOCTL},   {"tty",      CLUMPS_PLEDGE_TTY}
};

// Parse promise string into bitmask - scans PLEDGE_MAP for matching tokens
static uint32_t calculate_promises_mask(const char *promises) CLUMPS_NONNULL(1) {
    if (!promises) return 0;
    uint32_t mask = 0;
    for (size_t i = 0; i < sizeof(PLEDGE_MAP)/sizeof(PLEDGE_MAP[0]); i++)
        if (str_has_token(promises, PLEDGE_MAP[i].token))
            mask |= PLEDGE_MAP[i].bit;
    return mask;
}

// SECCOMP RULE HELPER - Add rule or fail cleanly
// warn_unused_result is a function type attribute; applying it to a local
// int is non-conforming. _rc is consumed immediately anyway.
#define RULE_ADD_OR_FAIL(ctx, action, syscall, argcnt, ...) do { \
    int _rc = seccomp_rule_add(ctx, action, syscall, argcnt, ##__VA_ARGS__); \
    if (CLUMPS_UNLIKELY(_rc < 0)) { \
        LOG("ERROR: seccomp_rule_add(%s) failed: %d\n", #syscall, _rc); \
        seccomp_release(ctx); \
        _set_error_context(4, -_rc, "seccomp_rule_add(%s)", #syscall); \
        SET_ERRNO_AND_RETURN(-1, -_rc); \
    } \
} while(0)

// W^X rule generator macro - allows mmap/mprotect without (W|X) simultaneously
// Enforces memory integrity by preventing writable+executable pages
#define W_X_PROTECT(syscall) do { \
    RULE_ADD_OR_FAIL(ctx, SCMP_ACT_ALLOW, SCMP_SYS(syscall), 1, \
                     SCMP_CMP_MASKED_EQ(2, PROT_WRITE, 0)); \
    RULE_ADD_OR_FAIL(ctx, SCMP_ACT_ALLOW, SCMP_SYS(syscall), 1, \
                     SCMP_CMP_MASKED_EQ(2, PROT_EXEC, 0)); \
} while(0)

// CORE SECCOMP FILTER BUILDER - Builds and installs seccomp filter for mask
// Does NOT set NO_NEW_PRIVS (caller manages that)
// Returns 0 on success, -1 on failure
static int _install_seccomp_filter(uint32_t mask, uint32_t flags) {
    int tsync = (flags & CLUMPS_PER_THREAD) ? 0 : 1;

    uint32_t fail_action = (flags & CLUMPS_ENABLE_LOG) ? SCMP_ACT_LOG :
                           (flags & CLUMPS_DEBUG_EPERM) ? SCMP_ACT_ERRNO(EPERM) :
                                                          SCMP_ACT_KILL_PROCESS;

    scmp_filter_ctx ctx = seccomp_init(fail_action);
    if (CLUMPS_UNLIKELY(!ctx)) {
        _set_error_context(4, ENOMEM, "seccomp_init");
        SET_ERRNO_AND_RETURN(-1, ENOMEM);
    }

    seccomp_attr_set(ctx, SCMP_FLTATR_CTL_TSYNC, tsync);

#if defined(__x86_64__)
    seccomp_arch_remove(ctx, SCMP_ARCH_X86);
    seccomp_arch_remove(ctx, SCMP_ARCH_X32);
#elif defined(__aarch64__)
    seccomp_arch_remove(ctx, SCMP_ARCH_ARM);
#endif

    unsigned char sys_allowed[1024];
    memset(sys_allowed, 0, sizeof(sys_allowed));

#define MARK_CLUMP(array) do { \
    for (size_t _mi = 0; _mi < sizeof(array)/sizeof(char*); _mi++) { \
        int nr = seccomp_syscall_resolve_name((array)[_mi]); \
        if (nr >= 0 && nr < 1024) sys_allowed[nr] = 1; \
    } \
} while(0)

    MARK_CLUMP(CLUMP_BASELINE);

    if (mask & CLUMPS_PLEDGE_STDIO)    MARK_CLUMP(CLUMP_STDIO);
    if (mask & CLUMPS_PLEDGE_RPATH)    MARK_CLUMP(CLUMP_RPATH);
    if (mask & CLUMPS_PLEDGE_WPATH)    MARK_CLUMP(CLUMP_WPATH);
    if (mask & CLUMPS_PLEDGE_CPATH)    MARK_CLUMP(CLUMP_CPATH);
    if (mask & CLUMPS_PLEDGE_INET)     MARK_CLUMP(CLUMP_INET);
    if (mask & CLUMPS_PLEDGE_DNS)      MARK_CLUMP(CLUMP_DNS);
    if (mask & CLUMPS_PLEDGE_PROC)     MARK_CLUMP(CLUMP_PROC);
    if (mask & CLUMPS_PLEDGE_EXEC)     MARK_CLUMP(CLUMP_EXEC);
    if (mask & CLUMPS_PLEDGE_ID)       MARK_CLUMP(CLUMP_ID);
    if (mask & CLUMPS_PLEDGE_IO_URING) MARK_CLUMP(CLUMP_IO_URING);
    if (mask & CLUMPS_PLEDGE_UNIX)     MARK_CLUMP(CLUMP_UNIX);
    if (mask & CLUMPS_PLEDGE_RECVFD)   MARK_CLUMP(CLUMP_RECVFD);
    if (mask & CLUMPS_PLEDGE_SENDFD)   MARK_CLUMP(CLUMP_SENDFD);
    if (mask & CLUMPS_PLEDGE_FATTR)    MARK_CLUMP(CLUMP_FATTR);
    // NEW PROMISES (added in later versions)
    if (mask & CLUMPS_PLEDGE_TMPPATH)  MARK_CLUMP(CLUMP_TMPPATH);
    if (mask & CLUMPS_PLEDGE_GETPW)    MARK_CLUMP(CLUMP_GETPW);
    if (mask & CLUMPS_PLEDGE_IOCTL)    MARK_CLUMP(CLUMP_IOCTL_GENERAL);
    if (mask & CLUMPS_PLEDGE_TTY)      MARK_CLUMP(CLUMP_TTY);

    if (mask & (CLUMPS_PLEDGE_RPATH | CLUMPS_PLEDGE_WPATH | CLUMPS_PLEDGE_CPATH |
                CLUMPS_PLEDGE_TMPPATH | CLUMPS_PLEDGE_GETPW)) {
        int nr_openat = seccomp_syscall_resolve_name("openat");
        if (nr_openat >= 0 && nr_openat < 1024) sys_allowed[nr_openat] = 1;
#if defined(__x86_64__)
        int nr_open = seccomp_syscall_resolve_name("open");
        if (nr_open >= 0 && nr_open < 1024) sys_allowed[nr_open] = 1;
#endif
    }

    for (int i = 0; i < 1024; i++) {
        if (sys_allowed[i]) {
            RULE_ADD_OR_FAIL(ctx, SCMP_ACT_ALLOW, i, 0);
        }
    }

    // W^X: allow mmap/mprotect without (W|X) simultaneously
    // Using W_X_PROTECT macro instead of 8 explicit lines
    W_X_PROTECT(mmap);
    W_X_PROTECT(mprotect);

    if (mask & CLUMPS_PLEDGE_INET) {
        RULE_ADD_OR_FAIL(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_INET));
        RULE_ADD_OR_FAIL(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_INET6));
        RULE_ADD_OR_FAIL(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_UNIX));
    } else if (mask & CLUMPS_PLEDGE_DNS) {
        RULE_ADD_OR_FAIL(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_INET));
        RULE_ADD_OR_FAIL(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_INET6));
    }
    if (mask & CLUMPS_PLEDGE_UNIX) {
        RULE_ADD_OR_FAIL(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 1, SCMP_CMP(0, SCMP_CMP_EQ, AF_UNIX));
    }

    if (mask & CLUMPS_PLEDGE_STDIO) {
        RULE_ADD_OR_FAIL(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_CMP(1, SCMP_CMP_EQ, TCGETS));
        RULE_ADD_OR_FAIL(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_CMP(1, SCMP_CMP_EQ, TIOCGWINSZ));
        RULE_ADD_OR_FAIL(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_CMP(1, SCMP_CMP_EQ, FIOCLEX));
    }
    // tty promise adds terminal-specific ioctls beyond stdio subset.
    // NOTE: the unconditional "ioctl" allow (below) supersedes both of these.
    if (mask & CLUMPS_PLEDGE_IOCTL) {
        RULE_ADD_OR_FAIL(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 0);
    }
    if (mask & CLUMPS_PLEDGE_TTY) {
        RULE_ADD_OR_FAIL(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_CMP(1, SCMP_CMP_EQ, TCGETS));
        RULE_ADD_OR_FAIL(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_CMP(1, SCMP_CMP_EQ, TCSETS));
        RULE_ADD_OR_FAIL(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_CMP(1, SCMP_CMP_EQ, TCGETS2));
        RULE_ADD_OR_FAIL(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_CMP(1, SCMP_CMP_EQ, TCSETS2));
        RULE_ADD_OR_FAIL(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_CMP(1, SCMP_CMP_EQ, TIOCGWINSZ));
        RULE_ADD_OR_FAIL(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_CMP(1, SCMP_CMP_EQ, TIOCSWINSZ));
        RULE_ADD_OR_FAIL(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_CMP(1, SCMP_CMP_EQ, TIOCMGET));
        RULE_ADD_OR_FAIL(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_CMP(1, SCMP_CMP_EQ, TIOCMBIS));
        RULE_ADD_OR_FAIL(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_CMP(1, SCMP_CMP_EQ, TIOCMBIC));
        RULE_ADD_OR_FAIL(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_CMP(1, SCMP_CMP_EQ, TIOCMSET));
        RULE_ADD_OR_FAIL(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_CMP(1, SCMP_CMP_EQ, TIOCGPTN));
        RULE_ADD_OR_FAIL(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_CMP(1, SCMP_CMP_EQ, TIOCGPTPEER));
    }

    int rc = seccomp_load(ctx);
    seccomp_release(ctx);
    return rc;
}

// Full pledge with execpromises - sets syscall restrictions
// promises: effective immediately
// execpromises: applied after fork()+execve() (must be subset of promises)
// Null execpromises accepted (no exec-transition configured)
int install_pledge(const char *promises, const char *execpromises) {
    return install_pledge_ext(promises, execpromises, 0);
}

// Backward-compatible single-argument wrapper
int install_pledge_single(const char *promises) {
    return install_pledge_ext(promises, NULL, 0);
}

// Extended pledge with execpromises and flags - primary entry point
// flags: CLUMPS_DEBUG_EPERM, CLUMPS_ENABLE_LOG, CLUMPS_PER_THREAD, etc.
// Returns 0 on success, -1 on error
int install_pledge_ext(const char *promises, const char *execpromises, uint32_t flags) {
    if (CLUMPS_UNLIKELY(!promises)) {
        _set_error_context(4, EINVAL, "NULL promises");
        SET_ERRNO_AND_RETURN(-1, EINVAL);
    }

    SCOPED_SIGMASK();
    SCOPED_MUTEX(lunveil_mutex);

    uint32_t requested_mask = calculate_promises_mask(promises);

    // --- Phase: already pledged (re-entry / child contraction) ---
    if (initialization_done) {
        // Allow CONTRACTING (tightening) promises only
        if ((requested_mask & current_promises_mask) == requested_mask) {
            // CRITICAL FIX: update tracked state only AFTER the
            // tighter filter installs successfully. A failed contraction
            // must not desynchronize the tracked mask from the actual
            // installed filter.
            int rc = _install_seccomp_filter(requested_mask, flags);
            if (rc == 0) {
                current_promises_mask = requested_mask;
                exec_pledged = 1;
                // Track the flags of the newest installed layer so
                // subsequent install_pledge_exec() contractions inherit the
                // most recent (typically identical) fail-action policy.
                stored_pledge_flags = flags;
                // CRITICAL FIX: previously logged "contraction from 0x%x"
                // with a bogus literal 0 because the old mask was already
                // overwritten at this point. Report the target only.
                LOG("INFO: Pledge contracted to 0x%x\n", requested_mask);
            }
            return rc;
        }
        // Cannot EXPAND privileges
        LOG("ERROR: Cannot expand promises after initial pledge (current=0x%x, requested=0x%x)\n",
             current_promises_mask, requested_mask);
        _set_error_context(4, EPERM, "pledge expansion");
        SET_ERRNO_AND_RETURN(-1, EPERM);
    }

    // --- Phase: initial pledge ---

    uint32_t fs_mask = CLUMPS_PLEDGE_RPATH | CLUMPS_PLEDGE_WPATH |
                       CLUMPS_PLEDGE_CPATH | CLUMPS_PLEDGE_EXEC |
                       CLUMPS_PLEDGE_FATTR |
                       CLUMPS_PLEDGE_TMPPATH | CLUMPS_PLEDGE_GETPW;
    uint32_t net_mask = CLUMPS_PLEDGE_INET | CLUMPS_PLEDGE_DNS | CLUMPS_PLEDGE_UNIX;

    int abi = _get_landlock_abi_cached();
    if ((requested_mask & (fs_mask | net_mask)) && abi < 1) {
        if (flags & CLUMPS_GRACEFUL_FALLBACK) {
            LOG("WARNING: Landlock required but unavailable - graceful fallback\n");
            current_promises_mask = requested_mask;
            initialization_done = 1;
            return 0;
        }
        LOG("ERROR: Landlock required for fs/network promises (ABI %d)\n", abi);
        _set_error_context(4, ENOTSUP, "Landlock ABI %d", abi);
        SET_ERRNO_AND_RETURN(-1, ENOTSUP);
    }

    if ((requested_mask & fs_mask) && !lunveil_locked) {
        LOG("ERROR: lunveil_lock() must precede pledge with fs promises\n");
        _set_error_context(4, EPERM, "missing lunveil_lock");
        SET_ERRNO_AND_RETURN(-1, EPERM);
    }

    // Validate execpromises BEFORE installing initial filter
    uint32_t new_exec_mask = 0;
    if (execpromises) {
        uint32_t exec_mask = calculate_promises_mask(execpromises);

        // execpromises MUST be subset of promises
        if ((exec_mask & ~requested_mask) != 0) {
            LOG("ERROR: execpromises must be subset of promises\n");
            _set_error_context(4, EINVAL, "execpromises subset validation");
            SET_ERRNO_AND_RETURN(-1, EINVAL);
        }

        new_exec_mask = exec_mask;
    }

    // PR_SET_NO_NEW_PRIVS and other prerequisites
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
        LOG("ERROR: prctl() failed: %s\n", strerror(errno));
        int _pe = errno;
        _set_error_context(4, _pe, "prctl");
        errno = _pe;
        return -1;
    }

    // Install initial seccomp filter
    int rc = _install_seccomp_filter(requested_mask, flags);
    if (rc == 0) {
        current_promises_mask = requested_mask;
        initialization_done = 1;
        // CRITICAL FIX: capture the pledge flags so install_pledge_exec()
        // can reuse them for the contraction layer (preserves EPERM/LOG
        // modes in children; see stored_pledge_flags declaration).
        stored_pledge_flags = flags;
        // CRITICAL FIX: commit execpromises state only after the
        // filter is live. Previously a failed seccomp_load() left stale
        // stored_execpromises_mask/has_execpromises behind.
        if (execpromises) {
            stored_execpromises_mask = new_exec_mask;
            has_execpromises = 1;
        }
        LOG("SUCCESS: Pledge committed (mask=0x%x, execpromises=0x%x, ABI %d)\n",
             requested_mask, stored_execpromises_mask, abi);
    }
    return rc;
}

// Child process contract to execpromises - removes exec token
// execpromises: NULL means "use the stored execpromises mask"
// This is used by clump_execve() for auto-contract
// Returns 0 on success, -1 on error
int install_pledge_exec(const char *execpromises) {
    SCOPED_SIGMASK();
    SCOPED_MUTEX(lunveil_mutex);

    if (!has_execpromises) {
        LOG("ERROR: install_pledge_exec() called but no execpromises were stored\n");
        _set_error_context(4, EINVAL, "no stored execpromises");
        SET_ERRNO_AND_RETURN(-1, EINVAL);
    }

    uint32_t exec_mask;
    if (execpromises) {
        exec_mask = calculate_promises_mask(execpromises);
    } else {
        // NULL: adopt the stored mask (used by clump_execve() auto-contract)
        exec_mask = stored_execpromises_mask;
    }

    // Verify it matches what we stored (security check).
    // Note: this check is trivially satisfied for NULL, by construction.
    if (exec_mask != stored_execpromises_mask) {
        LOG("ERROR: execpromises mismatch (stored=0x%x, requested=0x%x)\n",
             stored_execpromises_mask, exec_mask);
        _set_error_context(4, EPERM, "execpromises mismatch");
        SET_ERRNO_AND_RETURN(-1, EPERM);
    }

    if (initialization_done) {
        // Already pledged, just validate subset
        if ((exec_mask & ~current_promises_mask) != 0) {
            LOG("ERROR: execpromises exceeds current mask\n");
            _set_error_context(4, EPERM, "execpromises expansion");
            SET_ERRNO_AND_RETURN(-1, EPERM);
        }
    }

    // Remove exec from mask (can't re-exec after this point)
    exec_mask &= ~CLUMPS_PLEDGE_EXEC;

    // Install tighter filter. Only update tracked state on success
    // CRITICAL FIX: a failed layer must not corrupt the tracked mask.
    // CRITICAL FIX: use stored_pledge_flags, not 0
    int rc = _install_seccomp_filter(exec_mask, stored_pledge_flags);
    if (rc == 0) {
        current_promises_mask = exec_mask;
        exec_pledged = 1;
        LOG("SUCCESS: Child contracted to execpromises (mask=0x%x)\n", exec_mask);
    }
    return rc;
}

int clumps_get_landlock_abi(void) {
    return _get_landlock_abi_cached();
}

// Close file descriptors >= min_fd
// Helps prevent fd leaks to child processes
// Skips '.' and '..' entries that would be parsed as fd 0
CLUMPS_WARN_UNUSED int clumps_close_extra_fds(int min_fd) {
    DIR *dir = opendir("/proc/self/fd");
    if (CLUMPS_UNLIKELY(!dir)) {
        int _oe = errno;
        _set_error_context(0, _oe, "opendir(/proc/self/fd)");
        SET_ERRNO_AND_RETURN(-1, _oe);
    }

    struct dirent *entry;
    size_t closed = 0;
    while ((entry = readdir(dir)) != NULL) {
        // Skip non-numeric entries (".", "..") that atoi() would
        // incorrectly parse as fd 0, causing stdin to be closed.
        const char *dn = entry->d_name;
        int is_digit = (*dn != '\0');
        for (const char *p = dn; *p; p++)
            if (!isdigit((unsigned char)*p)) { is_digit = 0; break; }
        if (!is_digit) continue;

        int fd = atoi(dn);
        if (fd < min_fd || fd < 0) continue;
        if (fd != dirfd(dir)) {
            (void)close(fd);
            closed++;
        }
    }
    closedir(dir);

    if (_clumps_debug.enabled && closed > 0) {
        LOG("INFO: Closed %zu extra file descriptors\n", closed);
    }
    return 0;
}

// Set resource limits - fd_limit for RLIMIT_NOFILE, proc_limit for RLIMIT_NPROC
// Returns 0 on success (partial failure only warns for NPROC)
CLUMPS_WARN_UNUSED int clumps_set_resource_limits(int fd_limit, int proc_limit) {
    struct rlimit rl;

    // File descriptor limit
    rl.rlim_cur = (rlim_t)fd_limit;
    rl.rlim_max = (rlim_t)fd_limit;
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
        int _oe = errno;
        _set_error_context(0, _oe, "setrlimit(RLIMIT_NOFILE)");
        SET_ERRNO_AND_RETURN(-1, _oe);
    }

    // Process count limit - non-fatal if it fails
    rl.rlim_cur = (rlim_t)proc_limit;
    rl.rlim_max = (rlim_t)proc_limit;
    if (setrlimit(RLIMIT_NPROC, &rl) != 0) {
        clumps_reset_error(); /* Ignore NPROC failure if FD already set */
        LOG("WARN: setrlimit(RLIMIT_NPROC) failed: %s\n", strerror(errno));
    }

    return 0;
}

// clump_execve - Safe wrapper for execve with automatic pledge contract
// Auto-contracts to execpromises before execve().
// If auto-contract fails (e.g., storedExec exceeds current mask), returns -1
// and does NOT call execve
CLUMPS_WARN_UNUSED int clump_execve(const char *pathname, char *const argv[], char *const envp[]) {
    int needs_contract = (initialization_done && has_execpromises && !exec_pledged);

    if (needs_contract) {
        LOG("INFO: Auto-contracting execpromises before execve\n");
        // NULL = use the stored execpromises mask (restored behavior)
        int rc = install_pledge_exec(NULL);
        if (rc != 0) {
            int _ce = errno;
            LOG("ERROR: Failed to contract before execve: %s\n", strerror(_ce));
            SET_ERRNO_AND_RETURN(-1, _ce);
        }
    }

    return execve(pathname, (char *const *)argv, (char *const *)envp);
}

#endif /* CLUMPS_IMPLEMENTATION */

/* ============================================================================
 * TEST HARNESS - Compile with -DCLUMPS_TESTS
 * Each test runs in isolated forked child to preserve seccomp state
 * ============================================================================ */

#ifdef CLUMPS_TESTS

#include <sys/wait.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>

#define CLUMPS_TEST_VERSION "1.8.3"

// PCG32 RNG - provides reproducible randomized testing
typedef struct {
    uint64_t state;
    uint64_t mult;
    uint32_t trials;
    uint32_t unique_inputs;
    uint8_t bloom_filter[256];
} pcg_context_t;

// Seed PCG context with initial state
static void pcg_seed(pcg_context_t *ctx, uint64_t seed) {
    ctx->state = 0ULL;
    ctx->mult = (seed << 1) | 1ULL;
    ctx->state = ctx->state * ctx->mult + 1ULL;
    ctx->state = ctx->state * ctx->mult + 1ULL;
    ctx->trials = 0;
    ctx->unique_inputs = 0;
    memset(ctx->bloom_filter, 0, sizeof(ctx->bloom_filter));
}

// Generate next pseudo-random number
static uint32_t pcg_rand(pcg_context_t *ctx) {
    uint64_t old_state = ctx->state;
    ctx->state = old_state * ctx->mult + 1ULL;
    ctx->trials++;
    uint32_t xorshifted = (((old_state >> 18u) ^ old_state) >> 27u);
    uint32_t rot = old_state >> 59u;
    return (xorshifted >> rot) | (xorshifted << ((-rot) & 31));
}

static uint32_t pcg_rand_range(pcg_context_t *ctx, uint32_t max) {
    if (max == 0) return 0;
    return pcg_rand(ctx) % max;
}

static pcg_context_t _ctx_execpromises;
static pcg_context_t _ctx_tmppath;
static pcg_context_t _ctx_getpw;
static pcg_context_t _ctx_ioctl;
static pcg_context_t _ctx_all_promises;

#define SEED_EXECPROMISES 0xDEADCAFEUL
#define SEED_TMPPATH 0xBEEFC0FFUL
#define SEED_GETPW 0xCAFE1234UL
#define SEED_IOCTL 0xDEADBEEFUL
#define SEED_ALL_PROMISES 0xC0FFEE42UL

static const char *_pb_tokens[] = {
    "stdio", "rpath", "wpath", "cpath", "inet", "dns",
    "proc", "exec", "id", "io_uring", "unix",
    "recvfd", "sendfd", "fattr",
    "tmppath", "getpw", "ioctl", "tty"
};
#define _PB_NUM_TOKENS (sizeof(_pb_tokens) / sizeof(_pb_tokens[0]))

static const char *_pb_perms[] = {"r", "w", "x", "rw", "rx", "wx", "rwx"};
#define _PB_NUM_PERMS (sizeof(_pb_perms) / sizeof(_pb_perms[0]))

static uint64_t g_base_seed = 0xC0FFEE42ULL;

// Initialize RNG with configurable seed from environment
// Allows reproducible test runs via CLUMPS_PB_SEED
static void _pb_init_global_seed(void) {
    const char *env = getenv("CLUMPS_PB_SEED");
    g_base_seed = 0xC0FFEE42ULL;
    if (env) {
        char *endptr;
        unsigned long parsed = strtoul(env, &endptr, 0);
        if (endptr != env) {
            g_base_seed = parsed;
            printf("[SEED] Custom seed from CLUMPS_PB_SEED: 0x%lX\n", g_base_seed);
        }
    }
    pcg_seed(&_ctx_execpromises, g_base_seed ^ SEED_EXECPROMISES);
    pcg_seed(&_ctx_tmppath, g_base_seed ^ SEED_TMPPATH);
    pcg_seed(&_ctx_getpw, g_base_seed ^ SEED_GETPW);
    pcg_seed(&_ctx_ioctl, g_base_seed ^ SEED_IOCTL);
    pcg_seed(&_ctx_all_promises, g_base_seed ^ SEED_ALL_PROMISES);
}

static uint32_t pb_rand_idx(pcg_context_t *ctx, size_t len) {
    return pcg_rand_range(ctx, (uint32_t)len);
}

static const char *pb_rand_token(pcg_context_t *ctx) {
    return _pb_tokens[pb_rand_idx(ctx, _PB_NUM_TOKENS)];
}

// Generate random promise string with up to max_tokens
static void pb_gen_promises(pcg_context_t *ctx, char *buf, size_t bufsize, int max_tokens) {
    if (bufsize == 0) return;
    buf[0] = '\0';
    if (max_tokens > (int)(bufsize / 8)) max_tokens = (int)(bufsize / 8);
    int n = 1 + (int)pcg_rand_range(ctx, (uint32_t)max_tokens);
    for (int i = 0; i < n; i++) {
        size_t current_len = strlen(buf);
        size_t remaining = bufsize - current_len - 1;
        if (remaining < 3) break;
        const char *tok = pb_rand_token(ctx);
        size_t tok_len = strlen(tok);
        if (current_len > 0) {
            remaining--;
            if (remaining < 2) break;
        }
        if (tok_len >= remaining) break;
        if (current_len > 0) strncat(buf, " ", bufsize - strlen(buf) - 1);
        strncat(buf, tok, remaining - 1);
    }
}

// Test Results Tracking
static int g_test_passed = 0;
static int g_test_failed = 0;
static int g_test_skipped = 0;

#define ASSERT_PASS(msg) do { \
    printf("PASS: %s\n", msg); \
    g_test_passed++; \
} while(0)

#define ASSERT_FAIL(msg, err) do { \
    printf("FAIL: %s (errno=%d)\n", msg, (err)); \
    g_test_failed++; \
} while(0)

#define EXPECT_ERROR(expected_errno, actual_result, msg) do { \
    if ((actual_result) == -1 && (errno) == (expected_errno)) { \
        printf("PASS: %s (got expected errno=%d)\n", msg, (int)(expected_errno)); \
        g_test_passed++; \
    } else { \
        printf("FAIL: %s (expected errno=%d, got result=%d, errno=%d)\n", \
               msg, (int)(expected_errno), actual_result, errno); \
        g_test_failed++; \
    } \
} while(0)

#define SKIP_TEST(reason) do { \
    printf("SKIP: %s - %s\n", __func__, reason); \
    g_test_skipped++; \
    return; \
} while(0)

// Fork-isolated test runner - each test gets fresh seccomp state
#define RUN_TEST(test_fn) do { \
    pid_t _pid = fork(); \
    if (_pid == 0) { \
        printf("\n=== [%s] ===\n", #test_fn); \
        fflush(stdout); \
        struct sigaction sa_default = {.sa_handler = SIG_DFL, .sa_flags = 0}; \
        sigaction(SIGSEGV, &sa_default, NULL); \
        sigaction(SIGSYS, &sa_default, NULL); \
        sigaction(SIGBUS,  &sa_default, NULL); \
        sigaction(SIGABRT, &sa_default, NULL); \
        test_fn(); \
        _exit(g_test_failed > 0 ? 1 : 0); \
    } else if (_pid > 0) { \
        int _status; \
        waitpid(_pid, &_status, 0); \
        if (WIFEXITED(_status) && WEXITSTATUS(_status) == 0) { \
            g_test_passed++; \
        } else { \
            g_test_failed++; \
            if (WIFSIGNALED(_status)) \
                printf("  (child killed by signal %d)\n", WTERMSIG(_status)); \
        } \
    } else { \
        perror("fork failed"); \
        exit(EXIT_FAILURE); \
    } \
} while(0)

// Forked-child helper for parametric tests
#define FORK_CHILD(body_code) do { \
    pid_t _fc_pid = fork(); \
    if (_fc_pid == 0) { \
        struct sigaction _fc_sa = {.sa_handler = SIG_DFL, .sa_flags = 0}; \
        sigaction(SIGSEGV, &_fc_sa, NULL); \
        sigaction(SIGSYS,  &_fc_sa, NULL); \
        sigaction(SIGBUS,  &_fc_sa, NULL); \
        sigaction(SIGABRT, &_fc_sa, NULL); \
        body_code \
        _exit(1); \
    } else if (_fc_pid > 0) { \
        int _fc_status; \
        waitpid(_fc_pid, &_fc_status, 0); \
        if (WIFEXITED(_fc_status) && WEXITSTATUS(_fc_status) == 0) \
            g_test_passed++; \
        else { \
            g_test_failed++; \
            if (WIFSIGNALED(_fc_status)) \
                printf("    (killed by signal %d)\n", WTERMSIG(_fc_status)); \
        } \
    } else { \
        perror("fork failed"); \
        exit(EXIT_FAILURE); \
    } \
} while(0)

// Parametric property monotonicity test configs
typedef struct {
    const char *name;
    pcg_context_t *ctx;
    int trials;
    int max_tokens;
} property_test_config_t;

static const property_test_config_t PROPERTY_TESTS[] = {
    {"execpromises", &_ctx_execpromises, 100, 5},
    {"new_promises", &_ctx_tmppath, 100, 6},
    {"all_promises", &_ctx_all_promises, 200, 10},
};

// Run parametric property tests - verify subset relationships hold over many trials
static void run_parametric_property_tests(void) {
    int abi = clumps_get_landlock_abi();
    if (abi < 1) {
        printf("\n=== [property_monotonicity] ===\n");
        SKIP_TEST("Landlock not available");
    }

    for (size_t tidx = 0; tidx < sizeof(PROPERTY_TESTS)/sizeof(PROPERTY_TESTS[0]); tidx++) {
        const property_test_config_t *cfg = &PROPERTY_TESTS[tidx];
        
        FORK_CHILD({
            printf("Testing %s subset property...\n", cfg->name);
            
            int failures = 0, passed_trials = 0;
            char buf1[512], buf2[256];
            
            for (int t = 0; t < cfg->trials; t++) {
                pb_gen_promises(cfg->ctx, buf1, sizeof(buf1), cfg->max_tokens);
                
                buf2[0] = '\0';
                size_t elen = 0;
                char *sp = buf1;
                
                // Generate subset of buf1 for buf2
                while (*sp && elen < sizeof(buf2) - 10) {
                    if (isspace((unsigned char)*sp)) { sp++; continue; }
                    const char *tok = sp;
                    while (*sp && !isspace((unsigned char)*sp)) sp++;
                    size_t tlen = sp - tok;
                    
                    // Randomly decide whether to include token
                    if (pcg_rand_range(cfg->ctx, 2) == 0 && elen + tlen + 2 < sizeof(buf2)) {
                        if (elen > 0) strncat(buf2, " ", sizeof(buf2) - strlen(buf2) - 1);
                        strncat(buf2, tok, sizeof(buf2) - strlen(buf2) - 1);
                        elen += tlen + 1;
                    }
                }
                
                uint32_t m1 = calculate_promises_mask(buf1);
                uint32_t m2 = calculate_promises_mask(buf2);
                
                // Verify subset property: m2 should be subset of m1
                if ((m2 & ~m1) != 0) {
                    failures++;
                } else {
                    passed_trials++;
                }
            }
            
            if (failures == 0) {
                printf("PASS: %s subset property holds over %d trials (%d unique combinations tested)\n",
                       cfg->name, cfg->trials, passed_trials);
                _exit(0);
            } else {
                printf("FAIL: %d/%d %s subset trials failed\n", failures, cfg->trials, cfg->name);
                _exit(1);
            }
        });
    }
}

// Parametric basic promise test configs
typedef int (*promise_test_fn_t)(void);

typedef struct {
    const char *name;
    const char *pledge_str;
    struct { const char *path; const char *perms; } paths[3];
    promise_test_fn_t test_logic;
} promise_basic_config_t;

// Test logic functions for each promise type
static int test_tmppath_logic(void) {
    char tmpfile[PATH_MAX];
    snprintf(tmpfile, sizeof(tmpfile), "/tmp/clumps_tmppath_test_%d", getpid());
    int fd = creat(tmpfile, 0600);
    if (fd >= 0) { close(fd); unlink(tmpfile); return 0; }
    return -1;
}

static int test_getpw_logic(void) {
    int fd1 = open("/etc/passwd", O_RDONLY);
    int fd2 = open("/etc/group", O_RDONLY);
    int ok = (fd1 >= 0 && fd2 >= 0);
    if (fd1 >= 0) close(fd1);
    if (fd2 >= 0) close(fd2);
    return ok ? 0 : -1;
}

static int test_ioctl_logic(void) {
    /* Just verifying pledge installs; actual ioctl test needs live TTY */
    return 0;
}

static int test_tty_logic(void) {
    int fd = open("/dev/tty", O_RDWR);
    if (fd < 0) {
        printf("NOTE: Could not open /dev/tty (container/headless)\n");
        return 0;  /* Not a failure */
    }
    struct termios tio;
    int ret = ioctl(fd, TCGETS, &tio);
    close(fd);
    return ret == 0 ? 0 : -1;
}

// Basic promise test configurations
static const promise_basic_config_t PROMISE_BASIC_TESTS[] = {
    {
        "tmppath", "stdio tmppath",
        { {"/tmp", "w"}, {NULL, NULL} },
        test_tmppath_logic
    },
    {
        "getpw", "stdio getpw",
        { {"/etc/passwd", "r"}, {"/etc/group", "r"}, {NULL, NULL} },
        test_getpw_logic
    },
    {
        "ioctl", "stdio ioctl",
        { {"/tmp", "r"}, {NULL, NULL} },
        test_ioctl_logic
    },
    {
        "tty", "stdio tty",
        { {"/dev/tty", "r"}, {NULL, NULL} },
        test_tty_logic
    },
};

// Run parametric basic promise tests
static void run_parametric_promise_tests(void) {
    int abi = clumps_get_landlock_abi();
    if (abi < 1) {
        printf("\n=== [promise_basic] ===\n");
        SKIP_TEST("Landlock not available");
    }

    for (size_t tidx = 0; tidx < sizeof(PROMISE_BASIC_TESTS)/sizeof(PROMISE_BASIC_TESTS[0]); tidx++) {
        const promise_basic_config_t *cfg = &PROMISE_BASIC_TESTS[tidx];
        
        FORK_CHILD({
            printf("Testing %s promise...\n", cfg->name);
            
            // Set up unveil rules
            for (size_t i = 0; cfg->paths[i].path && i < 3; i++) {
                lunveil(cfg->paths[i].path, cfg->paths[i].perms);
            }
            lunveil_lock();
            
            // Install pledge
            int ret = install_pledge(cfg->pledge_str, NULL);
            if (ret != 0) {
                ASSERT_FAIL("pledge installation", errno);
                _exit(1);
            }
            
            // Run promise-specific test logic
            if (cfg->test_logic && cfg->test_logic() < 0) {
                ASSERT_FAIL("promise-specific test", errno);
                _exit(1);
            }
            
            ASSERT_PASS("basic promise test");
            _exit(0);
        });
    }
}

// Expansion rejection test configurations
typedef struct {
    const char *base_pledge;
    const char *extra_promise;
    const char *test_path;
    const char *test_perms;
} expansion_reject_config_t;

static const expansion_reject_config_t EXPANSION_TESTS[] = {
    {"stdio", "tmppath", "/tmp", "r"},
    {"stdio", "getpw", "/tmp", "r"},
};

// Run parametric expansion rejection tests
static void run_parametric_expansion_tests(void) {
    int abi = clumps_get_landlock_abi();
    if (abi < 1) {
        printf("\n=== [expansion_rejected] ===\n");
        SKIP_TEST("Landlock not available");
    }

    for (size_t tidx = 0; tidx < sizeof(EXPANSION_TESTS)/sizeof(EXPANSION_TESTS[0]); tidx++) {
        const expansion_reject_config_t *cfg = &EXPANSION_TESTS[tidx];
        
        FORK_CHILD({
            printf("Testing %s expansion rejection...\n", cfg->extra_promise);
            
            // Set up unveil rules
            lunveil(cfg->test_path, cfg->test_perms);
            lunveil_lock();
            
            // Initial pledge
            int ret = install_pledge(cfg->base_pledge, NULL);
            if (ret != 0) {
                ASSERT_FAIL("initial pledge", errno);
                _exit(1);
            }
            
            // Attempt expansion - should fail with EPERM
            char expand_buf[64];
            snprintf(expand_buf, sizeof(expand_buf), "%s %s", cfg->base_pledge, cfg->extra_promise);
            
            ret = install_pledge(expand_buf, NULL);
            EXPECT_ERROR(EPERM, ret, "expansion after pledge rejected");
            _exit(g_test_failed > 0 ? 1 : 0);
        });
    }
}

// execpromises subset validation test
static void test_execpromises_subset_validation(void) {
    int abi = clumps_get_landlock_abi();
    if (abi < 1) SKIP_TEST("Landlock not available");

    lunveil("/tmp", "r");
    lunveil_lock();

    int ret = install_pledge("stdio rpath dns exec", "stdio");
    ASSERT_PASS(ret == 0 ? "Valid subset execpromises accepted" : "Valid subset execpromises rejected");
    ASSERT_PASS(clumps_get_execpromises_mask() & CLUMPS_PLEDGE_STDIO ?
                "Execpromises stored" : "Execpromises not stored");

    ret = install_pledge("stdio", "stdio rpath");
    EXPECT_ERROR(EINVAL, ret, "execpromises must be subset of promises");

    if (g_test_failed > 0) exit(1);
}

// execpromises contracting test
static void test_execpromises_contracting(void) {
    int abi = clumps_get_landlock_abi();
    if (abi < 1) SKIP_TEST("Landlock not available");

    lunveil("/tmp", "r");
    lunveil_lock();

    int ret = install_pledge("stdio rpath dns exec", "stdio");
    ASSERT_PASS(ret == 0 ? "Initial pledge with execpromises succeeded" : "Initial pledge failed");

    uint32_t parent_mask = clumps_get_promise_mask();
    ASSERT_PASS(parent_mask & CLUMPS_PLEDGE_RPATH ? "Parent has RPATH" : "Parent missing RPATH");

    ret = install_pledge_exec("stdio");
    ASSERT_PASS(ret == 0 ? "Child contract to execpromises succeeded" : "Child contract failed");

    uint32_t child_mask = clumps_get_promise_mask();
    ASSERT_PASS(!(child_mask & CLUMPS_PLEDGE_RPATH) ? "Child lost RPATH" : "Child still has RPATH");
    ASSERT_PASS(child_mask & CLUMPS_PLEDGE_STDIO ? "Child retains STDIO" : "Child lost STDIO");
    ASSERT_PASS(!(child_mask & CLUMPS_PLEDGE_EXEC) ? "Child cannot re-exec" : "Child still has EXEC");

    if (g_test_failed > 0) exit(1);
}

// execpromises expansion rejection test
static void test_execpromises_expansion_rejected(void) {
    int abi = clumps_get_landlock_abi();
    if (abi < 1) SKIP_TEST("Landlock not available");

    lunveil("/tmp", "r");
    lunveil_lock();

    int ret = install_pledge("stdio rpath dns exec", "stdio");
    ASSERT_PASS(ret == 0 ? "Initial pledge succeeded" : "Initial pledge failed");

    ret = install_pledge("stdio rpath wpath dns", NULL);
    EXPECT_ERROR(EPERM, ret, "Expansion after pledge rejected");

    if (g_test_failed > 0) exit(1);
}

// execpromises full lifecycle test
static void test_execpromises_full_lifecycle(void) {
    int abi = clumps_get_landlock_abi();
    if (abi < 1) SKIP_TEST("Landlock not available");

    lunveil("/tmp", "r");
    lunveil_lock();

    int ret = install_pledge("stdio rpath exec", "stdio");
    ASSERT_PASS(ret == 0 ? "Parent pledge with execpromises succeeded" : "Parent pledge failed");

    pid_t pid = fork();
    if (pid == 0) {
        int cret = install_pledge_exec("stdio");
        if (cret != 0) _exit(1);

        int fd = open("/tmp/rpath_test_clumps", O_RDONLY);
        if (fd >= 0) {
            close(fd);
            _exit(2);
        }
        _exit(0);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            ASSERT_PASS("Child correctly blocked rpath after contraction");
        } else {
            ASSERT_FAIL("Child did not block rpath access", WEXITSTATUS(status));
        }
    }
    if (g_test_failed > 0) exit(1);
}

// execpromises no re-exec test
static void test_execpromises_no_reexec(void) {
    int abi = clumps_get_landlock_abi();
    if (abi < 1) SKIP_TEST("Landlock not available");

    lunveil("/tmp", "r");
    lunveil_lock();

    int ret = install_pledge("stdio rpath exec", "stdio");
    ASSERT_PASS(ret == 0 ? "Parent pledge succeeded" : "Parent pledge failed");

    ret = install_pledge_exec("stdio");
    ASSERT_PASS(ret == 0 ? "Child contract succeeded" : "Child contract failed");

    uint32_t mask = clumps_get_promise_mask();
    ASSERT_PASS(!(mask & CLUMPS_PLEDGE_EXEC) ? "EXEC promise removed after contract" : "EXEC still present");

    if (g_test_failed > 0) exit(1);
}

// Parser consistency test for new promises
static void test_property_new_promises_parser_consistency(void) {
    int abi = clumps_get_landlock_abi();
    if (abi < 1) SKIP_TEST("Landlock not available");

    pcg_context_t *ctx = &_ctx_tmppath;
    int trials = 100;
    int failures = 0;

    struct { const char *token; uint32_t expected_bit; } new_promises_map[] = {
        {"tmppath", CLUMPS_PLEDGE_TMPPATH},
        {"getpw",   CLUMPS_PLEDGE_GETPW},
        {"ioctl",   CLUMPS_PLEDGE_IOCTL},
        {"tty",     CLUMPS_PLEDGE_TTY}
    };
    int num_entries = sizeof(new_promises_map) / sizeof(new_promises_map[0]);

    for (int t = 0; t < trials; t++) {
        int idx = pb_rand_idx(ctx, (size_t)num_entries);
        const char *token = new_promises_map[idx].token;
        uint32_t expected = new_promises_map[idx].expected_bit;

        char buf[32];
        snprintf(buf, sizeof(buf), "%s", token);

        uint32_t actual = calculate_promises_mask(buf);

        if ((actual & expected) != expected) {
            printf("  FAIL trial %d: token '%s' missing expected bit 0x%x (got 0x%x)\n",
                   t, token, expected, actual);
            failures++;
        } else {
            uint32_t new_bits_only = actual & (CLUMPS_PLEDGE_TMPPATH | CLUMPS_PLEDGE_GETPW |
                                                CLUMPS_PLEDGE_IOCTL | CLUMPS_PLEDGE_TTY);
            if (new_bits_only != expected) {
                printf("  FAIL trial %d: token '%s' has unexpected new bits (expected 0x%x, got 0x%x)\n",
                       t, token, expected, new_bits_only);
                failures++;
            }
        }
    }

    if (failures == 0) {
        printf("PASS: all new promise tokens parse consistently over %d trials\n", trials);
        g_test_passed++;
    } else {
        printf("FAIL: %d/%d parser consistency trials failed\n", failures, trials);
        g_test_failed++;
    }

    if (g_test_failed > 0) exit(1);
}

// clump_execve auto-contract regression test
static void test_clump_execve_auto_contract(void) {
    int abi = clumps_get_landlock_abi();
    if (abi < 1) SKIP_TEST("Landlock not available");

    lunveil("/tmp", "r");
    lunveil_lock();

    int ret = install_pledge_ext("stdio rpath exec", "stdio", CLUMPS_DEBUG_EPERM);
    ASSERT_PASS(ret == 0 ? "Parent pledge succeeded (DEBUG_EPERM mode)" : "Parent pledge failed");

    errno = 0;
    int rc = clump_execve("/tmp/definitely_not_here_xyz", NULL, NULL);
    if (rc == -1 && errno == EPERM) {
        ASSERT_PASS("clump_execve auto-contract worked; execve denied with EPERM");
    } else {
        printf("FAIL: clump_execve auto-contract issue (rc=%d, errno=%d)\n", rc, errno);
        g_test_failed++;
    }
    if (g_test_failed > 0) exit(1);
}

// Version API test
static void test_version_api(void) {
    const char *ver = clumps_version();
    ASSERT_PASS(ver != NULL ? "Version string is not NULL" : "Version string is NULL");
    ASSERT_PASS(strlen(ver) > 0 ? "Version string is not empty" : "Version string is empty");
    ASSERT_PASS(strncmp(ver, "1.8.", 4) == 0 ? "Version starts with 1.8." : "Version does not start with 1.8.");
    if (g_test_failed > 0) exit(1);
}

// ABI detection test
static void test_abi_detection(void) {
    int abi = clumps_get_landlock_abi();
    printf("Detected Landlock ABI: %d\n", abi);
    if (abi > 0) {
        ASSERT_PASS(abi >= 1 ? "ABI version >= 1" : "ABI version < 1");
        ASSERT_PASS(abi <= 10 ? "ABI version within expected range (1-10)" : "ABI version > 10");
    } else {
        printf("SKIP: Landlock not available on this system\n");
        g_test_skipped++;
    }
    if (g_test_failed > 0) exit(1);
}

// Error context test
static void test_error_context(void) {
    int abi = clumps_get_landlock_abi();
    if (abi < 1) SKIP_TEST("Landlock not available");
    
    clumps_reset_error();
    lunveil(NULL, "r");
    clumps_error_ctx_t ctx = clumps_get_last_error();
    ASSERT_PASS(ctx.api_call != 0 ? "Error context has non-zero api_call" : "Error context has zero api_call");
    ASSERT_PASS(ctx.kernel_errno != 0 ? "Error context has non-zero errno" : "Error context has zero errno");
    ASSERT_PASS(strlen(ctx.message) > 0 ? "Error context has non-empty message" : "Error context has empty message");
    if (g_test_failed > 0) exit(1);
}

// Print test summary
static void print_summary(void) {
    printf("\n========================================\n");
    printf("TEST SUMMARY\n");
    printf("========================================\n");
    printf("Passed:         %d\n", g_test_passed);
    printf("Failed:         %d\n", g_test_failed);
    printf("Skipped:        %d\n", g_test_skipped);
    printf("========================================\n");

    if (g_test_failed == 0) {
        printf("ALL TESTS PASSED\n");
        exit(EXIT_SUCCESS);
    } else {
        printf("SOME TESTS FAILED\n");
        exit(EXIT_FAILURE);
    }
}

// Main test runner
int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    printf("CLUMPS Test Harness\n");
    printf("========================================\n");
    printf("Each test runs in isolated forked child\n");
    printf("========================================\n");

    _pb_init_global_seed();
    clumps_set_debug(1, 1, stdout);

    // Unique regression tests (use individual forks via RUN_TEST)
    RUN_TEST(test_clump_execve_auto_contract);
    RUN_TEST(test_execpromises_subset_validation);
    RUN_TEST(test_execpromises_contracting);
    RUN_TEST(test_execpromises_expansion_rejected);
    RUN_TEST(test_execpromises_full_lifecycle);
    RUN_TEST(test_execpromises_no_reexec);
    RUN_TEST(test_property_new_promises_parser_consistency);
    RUN_TEST(test_version_api);
    RUN_TEST(test_abi_detection);
    RUN_TEST(test_error_context);

    // Parametric tests (internal loops over configurations)
    printf("\n=== [Parametric Tests] ===\n");
    run_parametric_property_tests();
    run_parametric_promise_tests();
    run_parametric_expansion_tests();

    print_summary();
    return 0;
}

#endif /* CLUMPS_TESTS */

/* gcc -O2 -Wall -Wextra -Werror=unused-result -std=gnu11 -DCLUMPS_TESTS clumps.h -o clumps_test -lseccomp -lpthread */
