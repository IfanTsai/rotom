#include "breakpoint.hh"

#include <sys/ptrace.h>

// x86 instruction encoding for "int 3"
static const uint64_t int3 = 0xcc;

void Breakpoint::enable()
{
    long data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr);
    // save the data which is at the address which insert the breakpoint
    m_save_data = static_cast<uint8_t>(data & 0xff);
    // replace the data with "int 3" instruction to trigger a SIGTRAP
    ptrace(PTRACE_POKEDATA, m_pid, m_addr, (data & ~0xff) | int3);
    m_enable = true;
}

void Breakpoint::disable()
{
    long data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr);
    // restore the data which is at the address which insert the breakpoint
    ptrace(PTRACE_POKEDATA, m_pid, m_addr, (data & ~0xff) | m_save_data);
    m_enable = false;
}
