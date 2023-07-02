#include "debugger.hh"
#include "utils.hh"
#include "register.hh"

#include "linenoise.h"

#include <vector>
#include <iostream>
#include <sys/wait.h>
#include <sys/ptrace.h>

void Debugger::run()
{
    // wait for the child process to start
    wait_signal();

    char *line;
    while ( (line = linenoise("rotom> "))) {
        handle_command(line);
        linenoiseHistoryAdd(line);
        linenoiseFree(line);
    }
}

void Debugger::wait_signal()
{
    int wait_status;
    waitpid(m_pid, &wait_status, 0);
}

void Debugger::handle_command(const std::string &line)
{
    std::vector<std::string> args = split(line, ' ');
    std::string command = args[0];

    if (starts_with(command, "continue")) {
        continue_execution();
    } else if (starts_with(command, "break")) {
        std::string addr = args[1];
        if (starts_with(addr, "0x") || starts_with(addr, "0X")) {
            addr.erase(0, 2); // remove 0x or 0X
        }

        set_breakpoint_at_addr(std::stol(addr, 0, 16));
    } else if (starts_with(command, "register")) {
        if (starts_with(args[1], "dump")) {
            dump_registers();
        } else if (starts_with(args[1], "read")) {
            std::cout << "0x" << std::hex << get_register_value(m_pid, get_register_from_name(args[2])) << std::endl;
        } else if (starts_with(args[1], "write")) {
            std::string val = args[3];
            if (starts_with(val, "0x") || starts_with(val, "0X")) {
                val.erase(0, 2);
            }

            set_register_value(m_pid, get_register_from_name(args[2]), std::stol(val, 0, 16));
        }
    } else if (starts_with(command, "memory")) {
        std::string addr = args[2];
        if (starts_with(addr, "0x") || starts_with(addr, "0X")) {
            addr.erase(0, 2); // remove 0x or 0X
        }

        if (starts_with(args[1], "read")) {
            std::cout << std::hex << read_memory(std::stol(addr, 0, 16)) << std::endl;
        } else if (starts_with(args[1], "write")) {
            std::string val = args[3];
            if (starts_with(val, "0x") || starts_with(val, "0X")) {
                val.erase(0, 2);
            }

            write_memory(std::stol(addr, 0, 16), std::stol(val, 0, 16));
        }
    } else {
        std::cerr << "Unknown command" << std::endl;
    }
}

void Debugger::continue_execution()
{
    step_over_breakpoint();
    ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);

    wait_signal();
}

void Debugger::set_breakpoint_at_addr(const std::intptr_t addr)
{
    Breakpoint bp(m_pid, addr);
    bp.enable();
    m_breakpoints[addr] = bp;
}

void Debugger::dump_registers()
{
    for (const auto &rd : g_register_descriptors) {
        std::cout << rd.name << " 0x" << std::hex << get_register_value(m_pid, rd.reg) << std::endl;
    }
}

void Debugger::step_over_breakpoint()
{
    // - 1 because execution will go past the breakpoint
    uint64_t addr = get_pc() - 1;

    // check if the address is a breakpoint
    if (m_breakpoints.count(addr)) {
        Breakpoint &bp = m_breakpoints[addr];

        if (bp.is_enable()) {
            // if it is, pc back to the address
            set_pc(addr);

            // disable the breakpoint and recover the original instruction
            bp.disable();
            // step over the original instruction
            ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);

            wait_signal();

            // re-enable the breakpoint
            bp.enable();
        }
    }
}
