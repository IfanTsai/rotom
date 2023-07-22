#pragma once

#include "breakpoint.hh"
#include "register.hh"
#include "symbol.hh"

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
    class PtraceExprContext;

    std::string m_prog_name;
    pid_t m_pid;
    std::unordered_map<std::intptr_t, Breakpoint> m_breakpoints;
    dwarf::dwarf m_dwarf;
    elf::elf m_elf;
    uint64_t m_elf_addr_offset;

    uint64_t read_memory(uint64_t addr) const { return ptrace(PTRACE_PEEKDATA, m_pid, addr, nullptr); }

    void write_memory(uint64_t addr, uint64_t val) const { ptrace(PTRACE_POKEDATA, m_pid, addr, val); }

    uint64_t get_pc() const { return get_register_value(m_pid, Reg::rip); }

    void set_pc(uint64_t val) { set_register_value(m_pid, Reg::rip, val); }

    uint64_t get_elf_addr(uint64_t addr) { return addr - m_elf_addr_offset; }

    uint64_t get_load_addr(uint64_t addr) { return addr + m_elf_addr_offset; }

    uint64_t get_elf_pc() { return get_elf_addr(get_pc()); }

    void get_signal_info(siginfo_t *info) { ptrace(PTRACE_GETSIGINFO, m_pid, nullptr, info); }

    void wait_signal(bool slient=false);
    void handle_sigtrap(const siginfo_t *info);
    uint64_t get_elf_addr_offset();
    void handle_command(const std::string &line);
    void continue_execution();
    void set_breakpoint_at_addr(const uint64_t addr);
    void set_breakpoint_at_func(const std::string &name);
    void set_breakpoint_at_source_line(const std::string &file, uint64_t line);
    void remove_breakpoint(uint64_t addr);
    void dump_registers();
    void single_step_instruction(bool with_check_breakpoint=false);
    void step_over_breakpoint();
    void step_out();
    void step_in();
    void step_over();
    void print_source_code(const std::string &file_name, uint64_t line, uint64_t n_lines_context=2);
    void print_backtrace();
    void print_variables();
    dwarf::die get_func_die_from_addr(uint64_t addr);
    dwarf::line_table::iterator get_line_entry_from_addr(uint64_t addr);
    std::vector<Symbol> lookup_symbol(const std::string &name);
};

class Debugger::PtraceExprContext: public dwarf::expr_context {
public:
    PtraceExprContext(pid_t pid, uint64_t elf_addr_offset)
        : m_pid{pid}, m_elf_addr_offset(elf_addr_offset) {}

    dwarf::taddr reg(unsigned regnum) override
    {
        return get_register_value_from_dwarf_register(m_pid, regnum);
    }

    dwarf::taddr pc() override
    {
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, m_pid, nullptr, &regs);

        return regs.rip - m_elf_addr_offset;
    }

    dwarf::taddr deref_size(dwarf::taddr address, unsigned size) override
    {
        return ptrace(PTRACE_PEEKDATA, m_pid, address + m_elf_addr_offset, nullptr);
    }

private:
    pid_t m_pid;
    uint64_t m_elf_addr_offset;
};
