#pragma once

#include <cstdint>
#include <unistd.h>

class Breakpoint {
public:
    Breakpoint() = default;
    Breakpoint(pid_t pid, std::intptr_t addr)
        : m_pid(pid), m_addr(addr) {}

    bool is_enable() const { return m_enable; }
    intptr_t get_addr() const { return m_addr; }


    void enable();
    void disable();

private:
    pid_t m_pid;
    std::intptr_t m_addr;
    bool m_enable = false;
    uint8_t m_save_data;  // the address which insert the breakpoint
};

