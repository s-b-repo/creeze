#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/mman.h>

int main(int argc, char *argv[]) {
    pid_t pid;
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pid> <library_path>\n", argv[0]);
        return 1;
    }

    pid = atoi(argv[1]);
    char *lib_path = argv[2];

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace(PTRACE_ATTACH)");
        return 1;
    }

    waitpid(pid, NULL, 0);

    struct user_regs_struct regs, original_regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    memcpy(&original_regs, &regs, sizeof(struct user_regs_struct));

    void *dlopen_addr = dlsym(RTLD_NEXT, "dlopen");
    printf("dlopen address: %p\n", dlopen_addr);

    void *remote_lib_path_addr = mmap(NULL, strlen(lib_path) + 1, PROT_READ | PROT_WRITE,
                                      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (remote_lib_path_addr == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    ptrace(PTRACE_POKEDATA, pid, remote_lib_path_addr, lib_path);

    regs.eip = (long)dlopen_addr;
    regs.esp -= sizeof(void*);
    ptrace(PTRACE_POKEDATA, pid, regs.esp, remote_lib_path_addr);

    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ptrace(PTRACE_CONT, pid, NULL, NULL);

    waitpid(pid, NULL, 0);

    ptrace(PTRACE_SETREGS, pid, NULL, &original_regs);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    return 0;
}
