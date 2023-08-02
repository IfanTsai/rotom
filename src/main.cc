#include "debugger.hh"

#include "clipp.h"

#include <cstdio>
#include <cstring>
#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/ptrace.h>
#include <sys/personality.h>
#include <sys/prctl.h>

static void execute_debugee(const std::string &&prog)
{
    std::cout << "Executing debugee: " << prog << std::endl;
    pid_t pid = fork();
    if (pid < 0) {
        std::cerr << "Fork error: " << strerror(errno);
        exit(-1);
    } else if (pid > 0) {
        std::cout << "Started debugging process " << pid << std::endl;
        Debugger dbg(prog, pid);
        dbg.run();
    } else {
        ptrace(PTRACE_TRACEME, 0);
        personality(ADDR_NO_RANDOMIZE); // disable address space randomization
        execl(prog.c_str(), prog.c_str(), nullptr);
    }
}

static void attach_to_process(pid_t pid)
{
    ptrace(PTRACE_ATTACH, pid, nullptr, nullptr);

    std::cout << "Attached to process " << pid << std::endl;
    Debugger dbg("/proc/" + std::to_string(pid) + "/exe", pid);
    dbg.run();

    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
}

int main(int argc, char *argv[])
{
    enum class mode { exec, attach, help, unknown };
    mode selected_mode = mode::unknown;
    std::string prog;
    pid_t pid;

    auto exec_command = (
        clipp::command("exec").set(selected_mode, mode::exec).doc("execute a program"),
        clipp::value("program", prog)
    );

    auto attach_command = (
        clipp::command("attach").set(selected_mode, mode::attach).doc("attach to a running process"),
        clipp::value("pid", pid)
    );

    auto cli = (
        exec_command | attach_command
        | clipp::option("-h", "--help").set(selected_mode, mode::help).doc("show help")
        | clipp::option("-v", "--version").call([]{ std::cout << "Version 0.1" << std::endl; }).doc("show version")
    );

    auto usage = [&] {
        std::cout << "Usage: " << clipp::usage_lines(cli, argv[0], clipp::doc_formatting().first_column(0)) << std::endl;
        std::cout << std::endl << "Options:" << std::endl;
        std::cout << clipp::documentation(cli, clipp::doc_formatting().first_column(3)) << std::endl;
    };

    if (clipp::parse(argc, argv, cli)) {
        switch (selected_mode) {
        case mode::exec:
            execute_debugee(std::move(prog));
            break;
        case mode::attach:
            attach_to_process(pid);
            break;
        case mode::help:
            usage();
            break;
        default:
            break;
        }
    } else {
        usage();
    }

#if 0
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
    } else {
        execute_debugee(prog);
    }

    return 0;
#endif
}
