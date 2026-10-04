/* Benchmark-only launcher: measure the executed scanner, excluding Python heap. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    pid_t pid = fork();
    if (pid == 0) {
        execv(argv[1], argv + 1);
        _exit(2);
    }
    if (pid < 0) return 2;
    int status;
    struct rusage usage;
    while (wait4(pid, &status, 0, &usage) < 0) {
        if (errno != EINTR) return 2;
    }
    if (dprintf(3, "%ld\n", usage.ru_maxrss) < 0) return 2;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 2;
}
