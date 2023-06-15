#pragma once

#include "breakpoint.hh"
#include <string>
#include <unordered_map>

#include <unistd.h>

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

    void handle_command(const std::string &line);
    void continue_execution();
    void set_breakpoint_at_addr(const std::intptr_t addr);
};

