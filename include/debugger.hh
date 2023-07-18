#pragma once

#include "breakpoint.hh"
#include "register.hh"

#include "dwarf/dwarf++.hh"
#include "elf/elf++.hh"

#include <string>
#include <unordered_map>

#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>

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
    dwarf::dwarf m_dwarf;
    elf::elf m_elf;
    uint64_t m_elf_addr_offset;

    uint64_t read_memory(uint64_t addr) const { return ptrace(PTRACE_PEEKDATA, m_pid, addr, nullptr); }

    void write_memory(uint64_t addr, uint64_t val) const { ptrace(PTRACE_POKEDATA, m_pid, addr, val); }

    uint64_t get_pc() const { return get_register_value(m_pid, REG::rip); }

    void set_pc(uint64_t val) { set_register_value(m_pid, REG::rip, val); }

    uint64_t get_elf_addr(uint64_t addr) { return addr - m_elf_addr_offset; }

    void get_signal_info(siginfo_t *info) { ptrace(PTRACE_GETSIGINFO, m_pid, nullptr, info); }

    void wait_signal(bool slient=false);
    void handle_sigtrap(siginfo_t *info);
    uint64_t get_elf_addr_offset();
    void handle_command(const std::string &line);
    void continue_execution();
    void set_breakpoint_at_addr(const std::intptr_t addr);
    void dump_registers();
    void single_step_instruction(bool with_check_breakpoint=false);
    void step_over_breakpoint();
    void print_source_code(const std::string &file_name, uint64_t line, uint64_t n_lines_context=2);
    dwarf::die get_function_from_pc(uint64_t pc);
    dwarf::line_table::iterator get_line_entry_from_pc(uint64_t pc);
};

