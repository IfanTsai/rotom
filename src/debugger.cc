#include "debugger.hh"
#include "utils.hh"

#include "linenoise.h"

#include <vector>
#include <iostream>
#include <sys/wait.h>
#include <sys/ptrace.h>

void Debugger::run()
{
    int wait_status;
    waitpid(m_pid, &wait_status, 0);

    char *line;
    while ( (line = linenoise("rotom> "))) {
        handle_command(line);
        linenoiseHistoryAdd(line);
        linenoiseFree(line);
    }
}

void Debugger::handle_command(const std::string &line)
{
    std::vector<std::string> args = split(line, ' ');
    std::string command = args[0];

    if (starts_with(command, "continue")) {
        continue_execution();
    } else if (starts_with(command, "break")) {
        std::string addr = args[1];
        if (!starts_with(addr, "0x") && !starts_with(addr, "0X")) {
            std::cerr << "Breakpoint must be specified in hex" << std::endl;
            return;
        }

        addr.erase(0, 2); // remove 0x or 0X
        set_breakpoint_at_addr(std::stol(addr, 0, 16));
    } else {
        std::cerr << "Unknown command" << std::endl;
    }
}

void Debugger::continue_execution()
{
    ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);

    int wait_status;
    waitpid(m_pid, &wait_status, 0);
}

void Debugger::set_breakpoint_at_addr(const std::intptr_t addr)
{
    Breakpoint bp(m_pid, addr);
    bp.enable();
    m_breakpoints[addr] = bp;
}
