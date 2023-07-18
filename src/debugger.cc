#include "debugger.hh"
#include "utils.hh"
#include "register.hh"

#include "linenoise.h"

#include <vector>
#include <iostream>
#include <fstream>
#include <limits>
#include <iomanip>

#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

void Debugger::run()
{
    int fd = open(m_prog_name.c_str(), O_RDONLY);
    if (fd < 0) {
        std::cerr << "Failed to open " << m_prog_name << ", error: " << strerror(errno) << std::endl;
        exit(-1);
    }

    try {
        m_elf = elf::elf{elf::create_mmap_loader(fd)};
        m_dwarf = dwarf::dwarf{dwarf::elf::create_loader(m_elf)};
    } catch (const std::exception &e) {
        std::cerr << "Failed to run rotom: " << e.what() << std::endl;
        exit(-1);
    }

    m_elf_addr_offset = get_elf_addr_offset();

    // wait for the child process to start
    wait_signal(true);

    char *line;
    while ( (line = linenoise("rotom> ")) ) {
        handle_command(line);
        linenoiseHistoryAdd(line);
        linenoiseFree(line);
    }

    // exit debugger and kill deubugg process
    kill(m_pid, SIGKILL);
    waitpid(m_pid, nullptr, 0);
}

uint64_t Debugger::get_elf_addr_offset()
{
    // no need to offset if elf is position-dependent
    if (m_elf.get_hdr().type != elf::et::dyn) {
        return 0;
    }

    // use relative address in elf if it is position-independent,
    // so we need to offset running address

    // the offset is the load address which is found in /proc/<pid>/maps
    std::ifstream map("/proc/" + std::to_string(m_pid) + "/maps");
    std::string addr;
    std::getline(map, addr, '-');

    return std::stoull(addr, 0, 16);
}

void Debugger::wait_signal(bool slient)
{
    int wait_status;
    waitpid(m_pid, &wait_status, 0);

    if (slient) {
        return;
    }

    // get and parse debugger(sub process) signal
    siginfo_t siginfo;
    get_signal_info(&siginfo);
    switch (siginfo.si_signo) {
    case SIGTRAP:  // child process run into breakpoint
        handle_sigtrap(&siginfo);
        break;
    case SIGSEGV:
        std::cout << "Received SIGSEGV. Reason: " << siginfo.si_code << std::endl;
        break;
    default:
        std::cout << "Received signal " << strsignal(siginfo.si_signo) << std::endl;
    }
}

void Debugger::handle_sigtrap(siginfo_t *info) {
    switch (info->si_code) {
    // one of these cases will be set if a breakpoint was hit
    case SI_KERNEL:
    case TRAP_BRKPT: {
        // pc back to the address, - 1 because execution will go past the breakpoint
        set_pc(get_pc() - 1);
        std::cout << "Hit breakpoint at address 0x" << std::hex << get_pc() << std::endl;
        auto line_entry = get_line_entry_from_pc(get_elf_addr(get_pc()));
        print_source_code(line_entry->file->path, line_entry->line);
        return;
    }
    // this will be set if the signal was sent by single-stepping
    case TRAP_TRACE:
        return;
    default:
        std::cout << "Unknown SIGTRAP code " << info->si_code << std::endl;
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
    } else if (starts_with(command, "stepi")) {
        single_step_instruction(true);
        auto line_entry = get_line_entry_from_pc(get_elf_addr(get_pc()));
        print_source_code(line_entry->file->path, line_entry->line);
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
    uint64_t addr = get_pc();

    // check if the address is a breakpoint
    if (m_breakpoints.count(addr)) {
        Breakpoint &bp = m_breakpoints[addr];

        if (bp.is_enable()) {
            // disable the breakpoint and recover the original instruction
            bp.disable();

            // step over the original instruction
            single_step_instruction();

            // re-enable the breakpoint
            bp.enable();
        }
    }
}

void Debugger::single_step_instruction(bool with_check_breakpoint)
{
    if (with_check_breakpoint && m_breakpoints.count(get_pc())) {
        step_over_breakpoint();
    } else {
        ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
        wait_signal();
    }
}

void Debugger::print_source_code(const std::string &file_name, uint64_t line, uint64_t n_lines_context)
{
    std::ifstream file(file_name);

    auto start_line = line <= n_lines_context ? 1 : line - n_lines_context;
    auto end_line = line + n_lines_context + (line < n_lines_context ? n_lines_context - line : 0) + 1;

    // skip lines up until start_line
    for (auto i = 1; i < start_line; i++) {
        file.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }

    int line_number_align_width = std::to_string(end_line).size();
    std::cout << std::dec;

    // read and print lines up until end_line
    for (auto current_line = start_line; current_line <= end_line && file; current_line++) {
        std::string text;
        std::getline(file, text);

        // remove carriage return
        text.erase(std::remove(text.begin(), text.end(), '\r'), text.end());

        std::cout << (line == current_line ? "> " : "  ");
        std::cout << std::right << std::setw(line_number_align_width) <<  current_line << ": " << text << std::endl;
    }

    std::cout << std::endl;
}

dwarf::die Debugger::get_function_from_pc(uint64_t pc)
{
    for (auto &cu : m_dwarf.compilation_units()) {
        if (!dwarf::die_pc_range(cu.root()).contains(pc)) {
            continue;
        }

        for (const auto &die : cu.root()) {
            if (die.tag == dwarf::DW_TAG::subprogram && dwarf::die_pc_range(die).contains(pc)) {
                return die;
            }
        }
    }

    throw std::out_of_range{"Cannot find function"};
}

dwarf::line_table::iterator Debugger::get_line_entry_from_pc(uint64_t pc)
{
    for (auto &cu : m_dwarf.compilation_units()) {
        if (!dwarf::die_pc_range(cu.root()).contains(pc)) {
            continue;
        }

        auto &line_table = cu.get_line_table();
        auto it = line_table.find_address(pc);
        if (it == line_table.end()) {
            goto _exception;
        }

        return it;
   }

_exception:
    throw std::out_of_range("Cannot find line entry");
}
