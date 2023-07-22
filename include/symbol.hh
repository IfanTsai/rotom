#pragma once

#include "elf/elf++.hh"

#include <string>
#include <ostream>

enum class SymbolType {
    notype,
    object,
    func,
    section,
    file,
};

static std::ostream &operator<<(std::ostream &os, SymbolType type)
{
    switch (type) {
    case SymbolType::notype:
        return os << "notype";
    case SymbolType::object:
        return os << "object";
    case SymbolType::func:
        return os << "function";
    case SymbolType::section:
        return os << "section";
    case SymbolType::file:
        return os << "file";
    default:
        return os <<"unknown";
    }
}

struct Symbol {
    SymbolType type;
    std::string name;
    uint64_t addr;
};

static SymbolType get_symbol_type_from_elf_symbol_type(elf::stt sym_type)
{
    switch (sym_type) {
    case elf::stt::notype:
        return SymbolType::notype;
    case elf::stt::object:
        return SymbolType::object;
    case elf::stt::func:
        return SymbolType::func;
    case elf::stt::section:
        return SymbolType::section;
    case elf::stt::file:
        return SymbolType::file;
    default:
        return SymbolType::notype;
    }
}
