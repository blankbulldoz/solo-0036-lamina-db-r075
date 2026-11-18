/* fsync-fault injector for aarch64 Linux — a fault control, not a media model.
 *
 * Makes one specific fsync() fail with ENOSYS inside an already-running
 * process, so LaminaDB's durability boundary can be observed without a timing
 * race and without patching the product.
 *
 * Why this is needed: Append() does write() then Sync(). If Sync() fails, the
 * frame bytes are already in the page cache but the record was never
 * acknowledged. SIGKILL cannot separate "bytes reached the file" from "bytes
 * were lost" because the page cache survives the process. This injector
 * produces the real in-process error path so the two cases can be told apart
 * by inspection instead of assumption.
 *
 * It does NOT drop the page cache, and does NOT simulate loss of un-fsynced
 * bytes. Those need a block-device or namespace-level control this tool does
 * not provide.
 *
 * All threads are traced (PTRACE_O_TRACECLONE, per-thread bookkeeping). The Go
 * runtime is multi-threaded; tracing one thread silently misses the goroutine
 * that performs the commit, which would make the tool report a false negative.
 *
 * Entry vs exit is decided by PTRACE_GET_SYSCALL_INFO, not by guessing from
 * stop alternation: attaching to a running thread lands mid-syscall, so a
 * naive toggle is off by one and writes registers to the wrong stop.
 *
 * The syscall number is rewritten through NT_ARM_SYSTEM_CALL. On arm64 the x8
 * general-purpose register is NOT what the kernel dispatches on (x8 is only
 * the userspace calling convention; the kernel governs the number via its own
 * per-task syscallno). Writing x8 leaves the real number untouched and the
 * call silently succeeds, which produces a false "injected" report. This was
 * verified directly: x8 rewrite => fsync returns 0; NT_ARM_SYSTEM_CALL rewrite
 * => fsync returns -1/ENOSYS.
 *
 * Self-check: set NT_ARM_SYSTEM_CALL, read it back, and only claim an
 * injection when the read-back confirms the change.
 *
 * Usage:  fsync_inject <pid> [--target N] [--arm PATH]
 *   Fails the Nth fsync (1-based) counted after the file PATH appears.
 * Exit codes: 0 injected, 6 target never reached, 9 arm timed out.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <dirent.h>
#include <unistd.h>

#ifndef PTRACE_GET_SYSCALL_INFO
#define PTRACE_GET_SYSCALL_INFO 0x420e
#endif
#ifndef PTRACE_SYSCALL_INFO_ENTRY
#define PTRACE_SYSCALL_INFO_ENTRY 1
#define PTRACE_SYSCALL_INFO_EXIT 2
#define PTRACE_SYSCALL_INFO_SECCOMP 3
#endif

#define NT_PRSTATUS 1
#define NT_ARM_SYSTEM_CALL 0x404
#define A64_X8 8
#define A64_NREGS 34
#define SYS_fsync 82

struct a64_regs {
    uint64_t regs[A64_NREGS];
};

/* Kernel struct ptrace_syscall_info (include/uapi/linux/ptrace.h). */
struct syscall_info {
    uint8_t op;
    uint8_t pad[3];
    uint32_t arch;
    uint64_t instruction_pointer;
    uint64_t stack_pointer;
    union {
        struct {
            uint64_t nr;
            uint64_t args[6];
        } entry;
        struct {
            int64_t rval;
            uint8_t is_error;
        } exit;
        struct {
            uint64_t nr;
            uint64_t args[6];
            uint32_t ret_data;
        } seccomp;
    };
};

static int max_tids = 8192;
static pid_t *tids = NULL;
static int ntids = 0;
static int injected = 0;
static long target = 1;
static long seen = 0;
static char *arm_path = NULL;
static int armed = 0;

static int tid_index(pid_t t) {
    for (int i = 0; i < ntids; i++)
        if (tids[i] == t) return i;
    return -1;
}
static void tid_add(pid_t t) {
    if (tid_index(t) < 0 && ntids < max_tids) tids[ntids++] = t;
}
static void tid_del(pid_t t) {
    int i = tid_index(t);
    if (i >= 0) tids[i] = tids[--ntids];
}
static int set_syscall_nr(pid_t pid, int nr) {
    struct iovec io = {.iov_base = &nr, .iov_len = sizeof(nr)};
    return ptrace(PTRACE_SETREGSET, pid, (void *)NT_ARM_SYSTEM_CALL, &io);
}
static int get_syscall_nr(pid_t pid, int *nr) {
    struct iovec io = {.iov_base = nr, .iov_len = sizeof(*nr)};
    return ptrace(PTRACE_GETREGSET, pid, (void *)NT_ARM_SYSTEM_CALL, &io);
}
static int syscall_info(pid_t pid, struct syscall_info *si) {
    memset(si, 0, sizeof(*si));
    long rc = ptrace(PTRACE_GET_SYSCALL_INFO, pid, (void *)sizeof(*si), si);
    return rc > 0 && si->op != 0 ? 0 : -1;
}

/* Attach every thread that already exists. PTRACE_ATTACH on the main thread
 * does not cover its siblings, and the Go runtime keeps a pool of M's that
 * predate the attach. Missing them makes the tool report "not injected" while
 * the real commit fsync proceeds untouched on an untraced thread. */
static int attach_existing(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/task", pid);
    DIR *dir = opendir(path);
    if (!dir) return -1;
    pid_t list[8192];
    int n = 0;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL && n < 8192) {
        if (ent->d_name[0] == '.') continue;
        pid_t t = (pid_t)atoi(ent->d_name);
        if (t > 0) list[n++] = t;
    }
    closedir(dir);
    for (int i = 0; i < n; i++) {
        if (ptrace(PTRACE_ATTACH, list[i], 0, 0) != 0) continue;
        int st;
        waitpid(list[i], &st, __WALL);
        tid_add(list[i]);
        ptrace(PTRACE_SETOPTIONS, list[i], 0,
               (void *)(PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE));
        ptrace(PTRACE_SYSCALL, list[i], 0, 0);
    }
    return n;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s pid [--target N] [--arm PATH]\n", argv[0]);
        return 2;
    }
    pid_t pid = (pid_t)atoi(argv[1]);
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--target") && i + 1 < argc) target = atol(argv[++i]);
        else if (!strcmp(argv[i], "--arm") && i + 1 < argc) arm_path = argv[++i];
    }
    tids = calloc((size_t)max_tids, sizeof(pid_t));
    if (!tids) return 2;

    if (arm_path) {
        for (int i = 0; i < 120000 && access(arm_path, F_OK) != 0; i++)
            usleep(1000);
        if (access(arm_path, F_OK) != 0) {
            fprintf(stderr, "arm marker never appeared\n");
            return 9;
        }
        armed = 1;
    }

    if (ptrace(PTRACE_ATTACH, pid, 0, 0) != 0) {
        perror("attach");
        return 3;
    }
    int status;
    if (waitpid(pid, &status, __WALL) < 0) {
        perror("waitpid");
        return 5;
    }
    tid_add(pid);
    if (ptrace(PTRACE_SETOPTIONS, pid, 0,
               (void *)(PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE)) != 0) {
        perror("setoptions");
        return 4;
    }
    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) != 0) {
        perror("syscall");
        return 4;
    }
    int attached = attach_existing(pid);
    fprintf(stderr, "attached %d existing threads\n", attached);

    for (;;) {
        int st;
        pid_t who = waitpid(-1, &st, __WALL);
        if (who < 0) {
            if (errno == ECHILD) break;
            perror("waitpid");
            break;
        }
        if (WIFEXITED(st) || WIFSIGNALED(st)) {
            tid_del(who);
            if (ntids == 0) break;
            continue;
        }
        if (!WIFSTOPPED(st)) continue;
        int sig = WSTOPSIG(st);
        int event = (st >> 16) & 0xffff;

        if (sig == (SIGTRAP | 0x80)) {
            tid_add(who);
            struct syscall_info si;
            if (syscall_info(who, &si) == 0 &&
                si.op == PTRACE_SYSCALL_INFO_ENTRY &&
                si.entry.nr == SYS_fsync) {
                seen++;
                if (seen == target) {
                    /* -1 is not a valid syscall number: the kernel returns
                     * ENOSYS without performing the fsync. */
                    if (set_syscall_nr(who, -1) != 0) {
                        perror("set_syscall_nr");
                    } else {
                        int back = 0;
                        if (get_syscall_nr(who, &back) != 0) {
                            perror("get_syscall_nr");
                        } else if (back == -1) {
                            injected = 1;
                            fprintf(stderr,
                                    "injected ENOSYS on fsync #%ld (tid %d)\n",
                                    seen, who);
                            /* Detach everything and leave the process running.
                             * Continuing to trace would hold the server in
                             * syscall-stops and turn a clean experiment into a
                             * hang. */
                            for (int k = 0; k < ntids; k++)
                                ptrace(PTRACE_DETACH, tids[k], 0, 0);
                            fprintf(stderr, "detached %d threads\n", ntids);
                            free(tids);
                            return 0;
                        } else {
                            fprintf(stderr,
                                    "self-check failed: syscallno read back %d\n",
                                    back);
                        }
                    }
                }
            }
            ptrace(PTRACE_SYSCALL, who, 0, 0);
            continue;
        }

        if (event == PTRACE_EVENT_CLONE) {
            unsigned long newtid = 0;
            ptrace(PTRACE_GETEVENTMSG, who, 0, &newtid);
            tid_add((pid_t)newtid);
            sig = 0;
        }
        if (event != 0 || sig == SIGSTOP) sig = 0;
        ptrace(PTRACE_SYSCALL, who, 0, (void *)(long)sig);
    }
    fprintf(stderr, "finished injected=%d seen=%ld\n", injected, seen);
    free(tids);
    return injected ? 0 : 6;
}
