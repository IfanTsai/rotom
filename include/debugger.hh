#pragma once

#include "breakpoint.hh"
#include "register.hh"

#include <string>
#include <unordered_map>
#include <unistd.h>
#include <sys/ptrace.h>

class Debugger {
public:
    Debugger() = default;
    Debugger(std::string prog_name, pid_t pid)
        : m_prog_name(std::move(prog_name)), m_pid(pid) {}

    void run();
private:
    std::string m_prog_name;
    pid_t m_pid;
    std::unordered_map<std::intptr_t, Breakpoint> m_breakpoints;

    uint64_t read_memory(uint64_t addr) const { return ptrace(PTRACE_PEEKDATA, m_pid, addr, nullptr); }

    void write_memory(uint64_t addr, uint64_t val) const { ptrace(PTRACE_POKEDATA, m_pid, addr, val); }

    uint64_t get_pc() const { return get_register_value(m_pid, REG::rip); }

    void set_pc(uint64_t val) { set_register_value(m_pid, REG::rip, val); }

    void wait_signal();
    void handle_command(const std::string &line);
    void continue_execution();
    void set_breakpoint_at_addr(const std::intptr_t addr);
    void dump_registers();
    void step_over_breakpoint();
};

