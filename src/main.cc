#include "debugger.hh"

#include <cstdio>
#include <cstring>
#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/ptrace.h>
#include <sys/personality.h>

static inline void execute_debugee(const char *prog)
{
    ptrace(PTRACE_TRACEME, 0);
    personality(ADDR_NO_RANDOMIZE); // disable address space randomization
    execl(prog, prog, nullptr);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        std::cerr << "Please specify a program to debug" << std::endl;
        exit(-1);
    }

    const char *prog = argv[1];
    pid_t pid = fork();
    if (pid < 0) {
        std::cerr << "Fork error: " << strerror(errno);
        exit(-1);
    } else if (pid > 0) {
        std::cout << "Started debugging process " << pid << std::endl;
        Debugger dbg(prog, pid);
        dbg.run();
    }

    execute_debugee(prog);

    return 0;
}
