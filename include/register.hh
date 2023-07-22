#pragma once

#include <string>
#include <array>
#include <algorithm>
#include <stdexcept>

#include <cstdint>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/ptrace.h>

enum class Reg {
    rax, rbx, rcx, rdx,
    rdi, rsi, rbp, rsp,
    r8, r9, r10, r11,
    r12, r13, r14, r15,
    rip, rflags, cs,
    orig_rax, fs_base,
    gs_base,
    fs, gs, ss, ds, es
};

struct reg_descriptor {
    Reg reg;
    int dwarf_r;
    std::string name;
};

static constexpr std::size_t nr_registers = 27;
static const std::array<reg_descriptor, nr_registers> g_register_descriptors{{
    { Reg::r15, 15, "r15" },
    { Reg::r14, 14, "r14" },
    { Reg::r13, 13, "r13" },
    { Reg::r12, 12, "r12" },
    { Reg::rbp, 6,  "rbp" },
    { Reg::rbx, 3,  "rbx" },
    { Reg::r11, 11, "r11" },
    { Reg::r10, 10, "r10" },
    { Reg::r9,  9,  "r9" },
    { Reg::r8,  8,  "r8" },
    { Reg::rax, 0,  "rax" },
    { Reg::rcx, 2,  "rcx" },
    { Reg::rdx, 1, "rdx" },
    { Reg::rsi, 4, "rsi" },
    { Reg::rdi, 5, "rdi" },
    { Reg::orig_rax, -1, "orig_rax" },
    { Reg::rip, -1, "rip" },
    { Reg::cs,  51, "cs" },
    { Reg::rflags, 49, "eflags" },
    { Reg::rsp, 7, "rsp" },
    { Reg::ss,  52, "ss" },
    { Reg::fs_base, 58, "fs_base" },
    { Reg::gs_base, 59, "gs_base" },
    { Reg::ds,  53, "ds" },
    { Reg::es,  50, "es" },
    { Reg::fs,  54, "fs" },
    { Reg::gs,  55, "gs" },
}};

static unsigned long long *get_register_pointer(struct user_regs_struct &regs, Reg reg)
{
    switch (reg) {
        case Reg::rax: return &regs.rax;
        case Reg::rbx: return &regs.rbx;
        case Reg::rcx: return &regs.rcx;
        case Reg::rdx: return &regs.rdx;
        case Reg::rdi: return &regs.rdi;
        case Reg::rsi: return &regs.rsi;
        case Reg::rbp: return &regs.rbp;
        case Reg::rsp: return &regs.rsp;
        case Reg::r8:  return &regs.r8;
        case Reg::r9:  return &regs.r9;
        case Reg::r10: return &regs.r10;
        case Reg::r11: return &regs.r11;
        case Reg::r12: return &regs.r12;
        case Reg::r13: return &regs.r13;
        case Reg::r14: return &regs.r14;
        case Reg::r15: return &regs.r15;
        case Reg::rip: return &regs.rip;
        case Reg::rflags: return &regs.eflags;
        case Reg::cs:  return &regs.cs;
        case Reg::orig_rax: return &regs.orig_rax;
        case Reg::fs_base:  return &regs.fs_base;
        case Reg::gs_base:  return &regs.gs_base;
        case Reg::fs:  return &regs.fs;
        case Reg::gs:  return &regs.gs;
        case Reg::ss:  return &regs.ss;
        case Reg::ds:  return &regs.ds;
        case Reg::es:  return &regs.es;
        default: return nullptr;
    }
}

static inline uint64_t get_register_value(pid_t pid, Reg reg)
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);

    return *get_register_pointer(regs, reg);
}

static inline void set_register_value(pid_t pid, Reg reg, uint64_t value)
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);

    *get_register_pointer(regs, reg) = value;
    ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
}

static inline uint64_t get_register_value_from_dwarf_register(pid_t pid, unsigned int regnum)
{
    auto it = std::find_if(g_register_descriptors.begin(), g_register_descriptors.end(),
            [regnum](auto &&desc) { return desc.dwarf_r == regnum; });
    if (it == g_register_descriptors.end()) {
        throw std::out_of_range("Unknown dwarf register");
    }

    return get_register_value(pid, it->reg);
}

static inline std::string get_register_name(Reg reg)
{
    auto it = std::find_if(g_register_descriptors.begin(), g_register_descriptors.end(),
            [reg](auto &&desc) { return desc.reg == reg; });

    return it->name;
}

static inline Reg get_register_from_name(const std::string &name)
{
    auto it = std::find_if(g_register_descriptors.begin(), g_register_descriptors.end(),
            [name](auto &&desc) { return desc.name == name; });

    return it->reg;
}
