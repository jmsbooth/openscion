#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * TEST-ONLY LD_PRELOAD fault barrier for Linux. Never link into production.
 * The external supervisor sends SIGKILL after the barrier file appears.
 * No instrumentation or kill switches are introduced into OpenScion Rust.
 */
static void stop_at(const char *name) {
    const char *wanted = getenv("OPENSCION_TEST_FAULT_POINT");
    if (!wanted || strcmp(wanted, name) != 0) return;
    const char *ready = getenv("OPENSCION_TEST_READY_FILE");
    if (!ready || ready[0] != '/') _exit(118);
    int fd = open(ready, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    if (fd < 0) _exit(119);
    if (write(fd, name, strlen(name)) < 0) _exit(120);
    if (close(fd) < 0) _exit(121);
    for (;;) pause();
}

int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags) {
    static int (*real_fn)(int, const char *, int, const char *, int) = NULL;
    if (!real_fn) real_fn = dlsym(RTLD_NEXT, "linkat");
    if (!real_fn) _exit(122);
    int is_object = strstr(oldpath, ".openscion-object-") != NULL;
    if (is_object) stop_at("blob-before-link");
    int result = real_fn(olddirfd, oldpath, newdirfd, newpath, flags);
    if (is_object && result == 0) stop_at("blob-after-link");
    return result;
}

int fsync(int fd) {
    static int (*real_fn)(int) = NULL;
    if (!real_fn) real_fn = dlsym(RTLD_NEXT, "fsync");
    if (!real_fn) _exit(123);
    char proc[64], path[PATH_MAX];
    snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
    ssize_t len = readlink(proc, path, sizeof(path) - 1);
    if (len > 0) {
        path[len] = '\0';
        struct stat st;
        if (fstat(fd, &st) == 0) {
            const char *root = getenv("OPENSCION_TEST_ROOT");
            if (root && strstr(path, root) == path) {
                if (S_ISREG(st.st_mode) && strstr(path, ".openscion-object-")) {
                    stop_at("blob-before-stage-fsync");
                    int result = real_fn(fd);
                    if (result == 0) stop_at("blob-after-stage-fsync");
                    return result;
                }
                if (S_ISDIR(st.st_mode) &&
                    strstr(path, "/.openscion/objects/b1/"))
                    stop_at("blob-before-parent-fsync");
                if (S_ISDIR(st.st_mode) && strstr(path, ".openscion-checkout-"))
                    stop_at("checkout-before-stage-fsync");
                if (S_ISDIR(st.st_mode) && strcmp(path, root) == 0)
                    stop_at("checkout-after-publish");
            }
        }
    }
    return real_fn(fd);
}
