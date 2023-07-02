#pragma once

#include <string>
#include <array>
#include <algorithm>
#include <stdexcept>

#include <cstdint>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/ptrace.h>

enum class REG {
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
    REG reg;
    int dwarf_r;
    std::string name;
};

static constexpr std::size_t nr_registers = 27;
static const std::array<reg_descriptor, nr_registers> g_register_descriptors{{
    { REG::r15, 15, "r15" },
    { REG::r14, 14, "r14" },
    { REG::r13, 13, "r13" },
    { REG::r12, 12, "r12" },
    { REG::rbp, 6,  "rbp" },
    { REG::rbx, 3,  "rbx" },
    { REG::r11, 11, "r11" },
    { REG::r10, 10, "r10" },
    { REG::r9,  9,  "r9" },
    { REG::r8,  8,  "r8" },
    { REG::rax, 0,  "rax" },
    { REG::rcx, 2,  "rcx" },
    { REG::rdx, 1, "rdx" },
    { REG::rsi, 4, "rsi" },
    { REG::rdi, 5, "rdi" },
    { REG::orig_rax, -1, "orig_rax" },
    { REG::rip, -1, "rip" },
    { REG::cs,  51, "cs" },
    { REG::rflags, 49, "eflags" },
    { REG::rsp, 7, "rsp" },
    { REG::ss,  52, "ss" },
    { REG::fs_base, 58, "fs_base" },
    { REG::gs_base, 59, "gs_base" },
    { REG::ds,  53, "ds" },
    { REG::es,  50, "es" },
    { REG::fs,  54, "fs" },
    { REG::gs,  55, "gs" },
}};

static inline unsigned long long *get_register_pointer(struct user_regs_struct &regs, REG reg)
{
    switch (reg) {
        case REG::rax: return &regs.rax;
        case REG::rbx: return &regs.rbx;
        case REG::rcx: return &regs.rcx;
        case REG::rdx: return &regs.rdx;
        case REG::rdi: return &regs.rdi;
        case REG::rsi: return &regs.rsi;
        case REG::rbp: return &regs.rbp;
        case REG::rsp: return &regs.rsp;
        case REG::r8:  return &regs.r8;
        case REG::r9:  return &regs.r9;
        case REG::r10: return &regs.r10;
        case REG::r11: return &regs.r11;
        case REG::r12: return &regs.r12;
        case REG::r13: return &regs.r13;
        case REG::r14: return &regs.r14;
        case REG::r15: return &regs.r15;
        case REG::rip: return &regs.rip;
        case REG::rflags: return &regs.eflags;
        case REG::cs:  return &regs.cs;
        case REG::orig_rax: return &regs.orig_rax;
        case REG::fs_base:  return &regs.fs_base;
        case REG::gs_base:  return &regs.gs_base;
        case REG::fs:  return &regs.fs;
        case REG::gs:  return &regs.gs;
        case REG::ss:  return &regs.ss;
        case REG::ds:  return &regs.ds;
        case REG::es:  return &regs.es;
        default: return nullptr;
    }
}

static inline uint64_t get_register_value(pid_t pid, REG reg)
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);

    return *get_register_pointer(regs, reg);
}

static inline void set_register_value(pid_t pid, REG reg, uint64_t value)
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

static inline std::string get_register_name(REG reg)
{
    auto it = std::find_if(g_register_descriptors.begin(), g_register_descriptors.end(),
            [reg](auto &&desc) { return desc.reg == reg; });

    return it->name;
}

static inline REG get_register_from_name(const std::string &name)
{
    auto it = std::find_if(g_register_descriptors.begin(), g_register_descriptors.end(),
            [name](auto &&desc) { return desc.name == name; });

    return it->reg;
}
