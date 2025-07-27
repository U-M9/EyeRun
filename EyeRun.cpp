#include "EyeRun.h"
#include <Psapi.h>
#include <TlHelp32.h>
#include <cstring>

namespace EyeRun {

    namespace Tables {

        struct OpcodeEntry {
            const char* mnemonic;
            uint8_t operand_count;
            bool has_modrm;
            uint8_t default_operand_size;
        };

        static const std::unordered_map<uint16_t, OpcodeEntry> opcode_table = {

            {0x88, {"mov", 2, true, 1}},
            {0x89, {"mov", 2, true, 4}},
            {0x8A, {"mov", 2, true, 1}},
            {0x8B, {"mov", 2, true, 4}},
            {0x8C, {"mov", 2, true, 2}},
            {0x8D, {"lea", 2, true, 4}},
            {0x8E, {"mov", 2, true, 2}},
            {0xA0, {"mov", 2, false, 1}},
            {0xA1, {"mov", 2, false, 4}},
            {0xA2, {"mov", 2, false, 1}},
            {0xA3, {"mov", 2, false, 4}},
            {0xB0, {"mov", 2, false, 1}},
            {0xB8, {"mov", 2, false, 4}},
            {0xC6, {"mov", 2, true, 1}},
            {0xC7, {"mov", 2, true, 4}},

            {0x50, {"push", 1, false, 8}},
            {0x51, {"push", 1, false, 8}},
            {0x52, {"push", 1, false, 8}},
            {0x53, {"push", 1, false, 8}},
            {0x54, {"push", 1, false, 8}},
            {0x55, {"push", 1, false, 8}},
            {0x56, {"push", 1, false, 8}},
            {0x57, {"push", 1, false, 8}},
            {0x58, {"pop", 1, false, 8}},
            {0x59, {"pop", 1, false, 8}},
            {0x5A, {"pop", 1, false, 8}},
            {0x5B, {"pop", 1, false, 8}},
            {0x5C, {"pop", 1, false, 8}},
            {0x5D, {"pop", 1, false, 8}},
            {0x5E, {"pop", 1, false, 8}},
            {0x5F, {"pop", 1, false, 8}},
            {0x68, {"push", 1, false, 4}},
            {0x6A, {"push", 1, false, 1}},

            {0x00, {"add", 2, true, 1}},
            {0x01, {"add", 2, true, 4}},
            {0x02, {"add", 2, true, 1}},
            {0x03, {"add", 2, true, 4}},
            {0x04, {"add", 2, false, 1}},
            {0x05, {"add", 2, false, 4}},
            {0x28, {"sub", 2, true, 1}},
            {0x29, {"sub", 2, true, 4}},
            {0x2A, {"sub", 2, true, 1}},
            {0x2B, {"sub", 2, true, 4}},
            {0x2C, {"sub", 2, false, 1}},
            {0x2D, {"sub", 2, false, 4}},
            {0x80, {"add/sub/cmp", 2, true, 1}},
            {0x81, {"add/sub/cmp", 2, true, 4}},
            {0x83, {"add/sub/cmp", 2, true, 4}},
            {0xF6, {"test/not/neg/mul/imul/div/idiv", 1, true, 1}},
            {0xF7, {"test/not/neg/mul/imul/div/idiv", 1, true, 4}},
            {0xFE, {"inc/dec", 1, true, 1}},
            {0xFF, {"inc/dec/call/jmp/push", 1, true, 4}},

            {0x08, {"or", 2, true, 1}},
            {0x09, {"or", 2, true, 4}},
            {0x0A, {"or", 2, true, 1}},
            {0x0B, {"or", 2, true, 4}},
            {0x20, {"and", 2, true, 1}},
            {0x21, {"and", 2, true, 4}},
            {0x22, {"and", 2, true, 1}},
            {0x23, {"and", 2, true, 4}},
            {0x30, {"xor", 2, true, 1}},
            {0x31, {"xor", 2, true, 4}},
            {0x32, {"xor", 2, true, 1}},
            {0x33, {"xor", 2, true, 4}},

            {0x38, {"cmp", 2, true, 1}},
            {0x39, {"cmp", 2, true, 4}},
            {0x3A, {"cmp", 2, true, 1}},
            {0x3B, {"cmp", 2, true, 4}},
            {0x3C, {"cmp", 2, false, 1}},
            {0x3D, {"cmp", 2, false, 4}},
            {0x84, {"test", 2, true, 1}},
            {0x85, {"test", 2, true, 4}},
            {0xA8, {"test", 2, false, 1}},
            {0xA9, {"test", 2, false, 4}},

            {0xE8, {"call", 1, false, 4}},
            {0xE9, {"jmp", 1, false, 4}},
            {0xEB, {"jmp", 1, false, 1}},
            {0xC2, {"ret", 1, false, 2}},
            {0xC3, {"ret", 0, false, 0}},

            {0x70, {"jo", 1, false, 1}},
            {0x71, {"jno", 1, false, 1}},
            {0x72, {"jb", 1, false, 1}},
            {0x73, {"jnb", 1, false, 1}},
            {0x74, {"je", 1, false, 1}},
            {0x75, {"jne", 1, false, 1}},
            {0x76, {"jbe", 1, false, 1}},
            {0x77, {"ja", 1, false, 1}},
            {0x78, {"js", 1, false, 1}},
            {0x79, {"jns", 1, false, 1}},
            {0x7A, {"jp", 1, false, 1}},
            {0x7B, {"jnp", 1, false, 1}},
            {0x7C, {"jl", 1, false, 1}},
            {0x7D, {"jge", 1, false, 1}},
            {0x7E, {"jle", 1, false, 1}},
            {0x7F, {"jg", 1, false, 1}},

            {0x0F80, {"jo", 1, false, 4}},
            {0x0F81, {"jno", 1, false, 4}},
            {0x0F82, {"jb", 1, false, 4}},
            {0x0F83, {"jnb", 1, false, 4}},
            {0x0F84, {"je", 1, false, 4}},
            {0x0F85, {"jne", 1, false, 4}},
            {0x0F86, {"jbe", 1, false, 4}},
            {0x0F87, {"ja", 1, false, 4}},
            {0x0F88, {"js", 1, false, 4}},
            {0x0F89, {"jns", 1, false, 4}},
            {0x0F8A, {"jp", 1, false, 4}},
            {0x0F8B, {"jnp", 1, false, 4}},
            {0x0F8C, {"jl", 1, false, 4}},
            {0x0F8D, {"jge", 1, false, 4}},
            {0x0F8E, {"jle", 1, false, 4}},
            {0x0F8F, {"jg", 1, false, 4}},

            {0x90, {"nop", 0, false, 0}},
            {0x98, {"cwde", 0, false, 0}},
            {0x99, {"cdq", 0, false, 0}},
            {0xCC, {"int3", 0, false, 0}},
            {0xCD, {"int", 1, false, 1}},

            {0xA4, {"movsb", 0, false, 0}},
            {0xA5, {"movsd", 0, false, 0}},
            {0xA6, {"cmpsb", 0, false, 0}},
            {0xA7, {"cmpsd", 0, false, 0}},
            {0xAA, {"stosb", 0, false, 0}},
            {0xAB, {"stosd", 0, false, 0}},
            {0xAC, {"lodsb", 0, false, 0}},
            {0xAD, {"lodsd", 0, false, 0}},
            {0xAE, {"scasb", 0, false, 0}},
            {0xAF, {"scasd", 0, false, 0}},
        };
    }

    Operand Instruction::dummy_operand;

    static const std::unordered_map<Register, std::string> register_names = {

        {Register::RAX, "rax"}, {Register::RCX, "rcx"}, {Register::RDX, "rdx"}, {Register::RBX, "rbx"},
        {Register::RSP, "rsp"}, {Register::RBP, "rbp"}, {Register::RSI, "rsi"}, {Register::RDI, "rdi"},
        {Register::R8, "r8"}, {Register::R9, "r9"}, {Register::R10, "r10"}, {Register::R11, "r11"},
        {Register::R12, "r12"}, {Register::R13, "r13"}, {Register::R14, "r14"}, {Register::R15, "r15"},

        {Register::EAX, "eax"}, {Register::ECX, "ecx"}, {Register::EDX, "edx"}, {Register::EBX, "ebx"},
        {Register::ESP, "esp"}, {Register::EBP, "ebp"}, {Register::ESI, "esi"}, {Register::EDI, "edi"},
        {Register::R8D, "r8d"}, {Register::R9D, "r9d"}, {Register::R10D, "r10d"}, {Register::R11D, "r11d"},
        {Register::R12D, "r12d"}, {Register::R13D, "r13d"}, {Register::R14D, "r14d"}, {Register::R15D, "r15d"},

        {Register::AX, "ax"}, {Register::CX, "cx"}, {Register::DX, "dx"}, {Register::BX, "bx"},
        {Register::SP, "sp"}, {Register::BP, "bp"}, {Register::SI, "si"}, {Register::DI, "di"},

        {Register::AL, "al"}, {Register::CL, "cl"}, {Register::DL, "dl"}, {Register::BL, "bl"},
        {Register::AH, "ah"}, {Register::CH, "ch"}, {Register::DH, "dh"}, {Register::BH, "bh"},

        {Register::RIP, "rip"},
    };

    std::string Operand::to_string(bool intel_syntax) const {
        std::stringstream ss;

        switch (type) {
        case OperandType::Register:
        {
            auto it = register_names.find(reg);
            if (it != register_names.end()) {
                ss << it->second;
            }
            else {
                ss << "reg" << static_cast<int>(reg);
            }
        }
        break;

        case OperandType::Memory:
        {

            switch (mem_size) {
            case MemorySize::Byte: ss << "byte ptr "; break;
            case MemorySize::Word: ss << "word ptr "; break;
            case MemorySize::Dword: ss << "dword ptr "; break;
            case MemorySize::Qword: ss << "qword ptr "; break;
            default: break;
            }

            ss << "[";

            bool need_plus = false;

            if (base != Register::NONE) {
                auto base_it = register_names.find(base);
                if (base_it != register_names.end()) {
                    ss << base_it->second;
                    need_plus = true;
                }
            }

            if (index != Register::NONE) {
                if (need_plus) ss << "+";
                auto index_it = register_names.find(index);
                if (index_it != register_names.end()) {
                    ss << index_it->second;
                    if (scale > 1) {
                        ss << "*" << static_cast<int>(scale);
                    }
                    need_plus = true;
                }
            }

            if (displacement != 0 || (base == Register::NONE && index == Register::NONE)) {
                if (displacement < 0) {
                    ss << "-" << std::hex << -displacement;
                }
                else {
                    if (need_plus) ss << "+";
                    ss << std::hex << displacement;
                }
            }

            ss << "]";
        }
        break;

        case OperandType::Immediate:
            ss << std::hex << immediate;
            break;

        case OperandType::Relative:
            ss << std::hex << immediate;
            break;

        case OperandType::Absolute:
            ss << std::hex << immediate;
            break;

        default:
            break;
        }

        return ss.str();
    }

    bool Instruction::is_jump() const {
        return mnemonic.size() > 0 && mnemonic[0] == 'j';
    }

    bool Instruction::is_call() const {
        return mnemonic == "call";
    }

    bool Instruction::is_return() const {
        return mnemonic == "ret" || mnemonic == "retn";
    }

    bool Instruction::is_conditional() const {
        return is_jump() && mnemonic.size() > 1 && mnemonic != "jmp";
    }

    uintptr_t Instruction::get_branch_target() const {
        if (is_jump() || is_call()) {
            if (!operands.empty() && operands[0].type == OperandType::Relative) {
                return operands[0].immediate;
            }
        }
        return 0;
    }

    std::string Instruction::to_string(bool show_bytes, bool intel_syntax) const {
        std::stringstream ss;

        ss << std::hex << std::setw(16) << std::setfill('0') << address << ": ";

        if (show_bytes) {
            for (uint8_t byte : bytes) {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
            }

            for (size_t i = bytes.size(); i < 10; ++i) {
                ss << "   ";
            }
        }

        ss << std::setw(8) << std::setfill(' ') << std::left << mnemonic;

        if (!operands.empty()) {
            ss << " ";
            for (size_t i = 0; i < operands.size(); ++i) {
                if (i > 0) ss << ", ";
                ss << operands[i].to_string(intel_syntax);
            }
        }

        return ss.str();
    }

    bool MemoryRegion::is_readable() const {
        return (protection & PAGE_READONLY) ||
            (protection & PAGE_READWRITE) ||
            (protection & PAGE_EXECUTE_READ) ||
            (protection & PAGE_EXECUTE_READWRITE);
    }

    bool MemoryRegion::is_writable() const {
        return (protection & PAGE_READWRITE) ||
            (protection & PAGE_EXECUTE_READWRITE) ||
            (protection & PAGE_WRITECOPY) ||
            (protection & PAGE_EXECUTE_WRITECOPY);
    }

    bool MemoryRegion::is_executable() const {
        return (protection & PAGE_EXECUTE) ||
            (protection & PAGE_EXECUTE_READ) ||
            (protection & PAGE_EXECUTE_READWRITE) ||
            (protection & PAGE_EXECUTE_WRITECOPY);
    }

    bool MemoryRegion::is_guard_page() const {
        return (protection & PAGE_GUARD) != 0;
    }

    bool MemoryRegion::contains(uintptr_t address) const {
        return address >= base && address < base + size;
    }

    std::string MemoryRegion::protection_string() const {
        std::string result;

        if (protection & PAGE_EXECUTE) result += "X";
        else result += "-";

        if (is_readable()) result += "R";
        else result += "-";

        if (is_writable()) result += "W";
        else result += "-";

        if (protection & PAGE_GUARD) result += "G";

        return result;
    }

    bool SectionInfo::is_executable() const {
        return (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    }

    bool SectionInfo::is_readable() const {
        return (characteristics & IMAGE_SCN_MEM_READ) != 0;
    }

    bool SectionInfo::is_writable() const {
        return (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    }

    std::optional<SectionInfo> ModuleInfo::find_section(const std::string& name) const {
        for (const auto& section : sections) {
            if (section.name == name) {
                return section;
            }
        }
        return std::nullopt;
    }

    std::optional<SectionInfo> ModuleInfo::find_section_by_address(uintptr_t address) const {
        uintptr_t rva = address - base;

        for (const auto& section : sections) {
            if (rva >= section.virtual_address && rva < section.virtual_address + section.virtual_size) {
                return section;
            }
        }
        return std::nullopt;
    }

    ProcessInfo::ProcessInfo(HANDLE process) : process_handle(process) {
        external_mode = (process != GetCurrentProcess());
        if (!external_mode) {
            process_id = GetCurrentProcessId();
        }
        else {
            process_id = GetProcessId(process);
        }
    }

    ProcessInfo::~ProcessInfo() {
        if (owns_handle && process_handle && process_handle != GetCurrentProcess()) {
            CloseHandle(process_handle);
        }
    }

    bool ProcessInfo::attach(const std::string& process_name) {
        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(PROCESSENTRY32);

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            return false;
        }

        bool found = false;
        if (Process32First(snapshot, &entry)) {
            do {
                if (process_name == entry.szExeFile) {
                    found = true;
                    break;
                }
            } while (Process32Next(snapshot, &entry));
        }

        CloseHandle(snapshot);

        if (!found) {
            return false;
        }

        return attach(entry.th32ProcessID);
    }

    bool ProcessInfo::attach(DWORD pid) {
        if (owns_handle && process_handle && process_handle != GetCurrentProcess()) {
            CloseHandle(process_handle);
        }

        process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!process_handle) {
            return false;
        }

        process_id = pid;
        external_mode = true;
        owns_handle = true;
        modules_cached = false;
        return true;
    }

    void ProcessInfo::detach() {
        if (owns_handle && process_handle && process_handle != GetCurrentProcess()) {
            CloseHandle(process_handle);
            process_handle = nullptr;
            owns_handle = false;
            external_mode = false;
            modules_cached = false;
        }
    }

    bool ProcessInfo::read_memory(uintptr_t address, void* buffer, size_t size) const {
        if (!external_mode) {

            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0)
                return false;
            if (!(mbi.State & MEM_COMMIT))
                return false;
            if ((mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD))
                return false;

            if ((address + size) > (reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize))
                return false;

            __try {
                memcpy(buffer, reinterpret_cast<const void*>(address), size);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                return false;
            }
        }
        if (!external_mode) {

            __try {
                memcpy(buffer, reinterpret_cast<const void*>(address), size);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                return false;
            }
        }
    }

    bool ProcessInfo::write_memory(uintptr_t address, const void* buffer, size_t size) {
        if (!external_mode) {

            DWORD old_protect;
            if (!VirtualProtect(reinterpret_cast<LPVOID>(address), size, PAGE_EXECUTE_READWRITE, &old_protect)) {
                return false;
            }

            __try {
                memcpy(reinterpret_cast<void*>(address), buffer, size);
                VirtualProtect(reinterpret_cast<LPVOID>(address), size, old_protect, &old_protect);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                VirtualProtect(reinterpret_cast<LPVOID>(address), size, old_protect, &old_protect);
                return false;
            }
        }

        SIZE_T bytes_written;
        return WriteProcessMemory(process_handle, reinterpret_cast<LPVOID>(address),
            buffer, size, &bytes_written) && bytes_written == size;
    }

    std::vector<MemoryRegion> ProcessInfo::enumerate_regions() const {
        std::vector<MemoryRegion> regions;
        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t address = 0;

        while (VirtualQueryEx(process_handle, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT) {
                MemoryRegion region;
                region.base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                region.size = mbi.RegionSize;
                region.protection = mbi.Protect;
                region.state = mbi.State;
                region.type = mbi.Type;

                for (const auto& module : enumerate_modules()) {
                    if (region.base >= module.base && region.base < module.base + module.size) {
                        region.module_name = module.name;
                        break;
                    }
                }

                regions.push_back(region);
            }

            address = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        }

        return regions;
    }

    std::optional<MemoryRegion> ProcessInfo::find_region(uintptr_t address) const {
        MEMORY_BASIC_INFORMATION mbi;

        if (VirtualQueryEx(process_handle, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT) {
                MemoryRegion region;
                region.base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                region.size = mbi.RegionSize;
                region.protection = mbi.Protect;
                region.state = mbi.State;
                region.type = mbi.Type;
                return region;
            }
        }

        return std::nullopt;
    }

    void ProcessInfo::refresh_module_cache() const {
        module_cache.clear();

        if (!external_mode) {

            HMODULE modules[1024];
            DWORD needed;

            if (EnumProcessModules(process_handle, modules, sizeof(modules), &needed)) {
                for (size_t i = 0; i < (needed / sizeof(HMODULE)); i++) {
                    ModuleInfo info;
                    char module_name[MAX_PATH];

                    if (GetModuleFileNameExA(process_handle, modules[i], module_name, sizeof(module_name))) {
                        info.path = module_name;
                        info.name = strrchr(module_name, '\\') ? strrchr(module_name, '\\') + 1 : module_name;
                        info.base = reinterpret_cast<uintptr_t>(modules[i]);
                        info.handle = modules[i];

                        MODULEINFO mod_info;
                        if (GetModuleInformation(process_handle, modules[i], &mod_info, sizeof(mod_info))) {
                            info.size = mod_info.SizeOfImage;
                        }

                        info.sections = read_sections(info.base);

                        module_cache.push_back(info);
                    }
                }
            }
        }
        else {

            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);
            if (snapshot != INVALID_HANDLE_VALUE) {
                MODULEENTRY32 entry;
                entry.dwSize = sizeof(MODULEENTRY32);

                if (Module32First(snapshot, &entry)) {
                    do {
                        ModuleInfo info;
                        info.name = entry.szModule;
                        info.path = entry.szExePath;
                        info.base = reinterpret_cast<uintptr_t>(entry.modBaseAddr);
                        info.size = entry.modBaseSize;
                        info.handle = entry.hModule;

                        info.sections = read_sections(info.base);

                        module_cache.push_back(info);
                    } while (Module32Next(snapshot, &entry));
                }

                CloseHandle(snapshot);
            }
        }

        modules_cached = true;
    }

    std::vector<ModuleInfo> ProcessInfo::enumerate_modules() const {
        if (!modules_cached) {
            refresh_module_cache();
        }
        return module_cache;
    }

    std::optional<ModuleInfo> ProcessInfo::find_module(const std::string& module_name) const {
        auto modules = enumerate_modules();

        for (const auto& module : modules) {
            if (module.name.find(module_name) != std::string::npos) {
                return module;
            }
        }

        return std::nullopt;
    }

    uintptr_t ProcessInfo::get_module_base(const std::string& module_name) const {
        auto module = find_module(module_name);
        return module ? module->base : 0;
    }

    uintptr_t ProcessInfo::get_proc_address(const std::string& module_name, const std::string& proc_name) const {
        if (!external_mode) {
            HMODULE module = GetModuleHandleA(module_name.c_str());
            if (module) {
                return reinterpret_cast<uintptr_t>(GetProcAddress(module, proc_name.c_str()));
            }
        }

        return 0;
    }

    std::optional<IMAGE_DOS_HEADER> ProcessInfo::read_dos_header(uintptr_t base) const {
        IMAGE_DOS_HEADER dos_header;

        if (read_memory(base, &dos_header, sizeof(dos_header))) {
            if (dos_header.e_magic == IMAGE_DOS_SIGNATURE) {
                return dos_header;
            }
        }

        return std::nullopt;
    }

    std::optional<IMAGE_NT_HEADERS64> ProcessInfo::read_nt_headers(uintptr_t base) const {
        auto dos_header = read_dos_header(base);
        if (!dos_header) {
            return std::nullopt;
        }

        IMAGE_NT_HEADERS64 nt_headers;

        if (read_memory(base + dos_header->e_lfanew, &nt_headers, sizeof(nt_headers))) {
            if (nt_headers.Signature == IMAGE_NT_SIGNATURE) {
                return nt_headers;
            }
        }

        return std::nullopt;
    }

    std::vector<SectionInfo> ProcessInfo::read_sections(uintptr_t base) const {
        std::vector<SectionInfo> sections;

        auto nt_headers = read_nt_headers(base);
        if (!nt_headers) {
            return sections;
        }

        uintptr_t section_addr = base + read_dos_header(base)->e_lfanew +
            sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
            nt_headers->FileHeader.SizeOfOptionalHeader;

        for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
            IMAGE_SECTION_HEADER section_header;

            if (read_memory(section_addr, &section_header, sizeof(section_header))) {
                SectionInfo info;
                info.name = std::string(reinterpret_cast<char*>(section_header.Name), 8);
                info.name = info.name.c_str();
                info.virtual_address = section_header.VirtualAddress;
                info.virtual_size = section_header.Misc.VirtualSize;
                info.raw_address = section_header.PointerToRawData;
                info.raw_size = section_header.SizeOfRawData;
                info.characteristics = section_header.Characteristics;

                sections.push_back(info);
            }

            section_addr += sizeof(IMAGE_SECTION_HEADER);
        }

        return sections;
    }

    bool ProcessInfo::is_x64() const {
        if (!external_mode) {
            return sizeof(void*) == 8;
        }

        BOOL is_wow64 = FALSE;
        IsWow64Process(process_handle, &is_wow64);
        return !is_wow64;
    }

    uintptr_t ProcessInfo::allocate(size_t size, DWORD protection) {
        void* addr = VirtualAllocEx(process_handle, nullptr, size,
            MEM_COMMIT | MEM_RESERVE, protection);
        return reinterpret_cast<uintptr_t>(addr);
    }

    bool ProcessInfo::free(uintptr_t address) {
        return VirtualFreeEx(process_handle, reinterpret_cast<LPVOID>(address), 0, MEM_RELEASE);
    }

    struct Disassembler::DecodingContext {
        const uint8_t* data = nullptr;
        size_t offset = 0;
        size_t max_size = 0;
        uintptr_t address = 0;

        Prefixes prefixes;
        uint16_t opcode = 0;
        bool has_modrm = false;
        uint8_t modrm = 0;
        bool has_sib = false;
        uint8_t sib = 0;
        int64_t displacement = 0;
        uint64_t immediate = 0;

        uint8_t operand_size = 4;
        uint8_t address_size = 8;
        uint8_t vector_length = 16;

        uint8_t read_u8() {
            if (offset >= max_size) return 0;
            return data[offset++];
        }

        uint16_t read_u16() {
            if (offset + 1 >= max_size) return 0;
            uint16_t value = *reinterpret_cast<const uint16_t*>(&data[offset]);
            offset += 2;
            return value;
        }

        uint32_t read_u32() {
            if (offset + 3 >= max_size) return 0;
            uint32_t value = *reinterpret_cast<const uint32_t*>(&data[offset]);
            offset += 4;
            return value;
        }

        uint64_t read_u64() {
            if (offset + 7 >= max_size) return 0;
            uint64_t value = *reinterpret_cast<const uint64_t*>(&data[offset]);
            offset += 8;
            return value;
        }

        uint8_t peek_u8() const {
            if (offset >= max_size) return 0;
            return data[offset];
        }

        uint8_t modrm_mod() const { return (modrm >> 6) & 0x03; }
        uint8_t modrm_reg() const { return (modrm >> 3) & 0x07; }
        uint8_t modrm_rm() const { return modrm & 0x07; }

        uint8_t sib_scale() const { return (sib >> 6) & 0x03; }
        uint8_t sib_index() const { return (sib >> 3) & 0x07; }
        uint8_t sib_base() const { return sib & 0x07; }
    };

    bool Disassembler::decode_instruction(DecodingContext& ctx, Instruction& inst) {

        size_t start_offset = ctx.offset;

        if (!decode_prefixes(ctx)) {
            return false;
        }

        if (!decode_opcode(ctx)) {
            return false;
        }

        decode_operands(ctx, inst);

        inst.address = ctx.address;
        inst.prefixes = ctx.prefixes;
        inst.length = ctx.offset;
        inst.bytes.assign(ctx.data, ctx.data + inst.length);

        handle_rip_relative(ctx, inst);

        if (ctx.prefixes.lock) {
            inst.set_flag(InstructionFlags::LockPrefix);
        }
        if (ctx.prefixes.repe || ctx.prefixes.repne) {
            inst.set_flag(InstructionFlags::RepeatPrefix);
        }
        if (inst.is_rip_relative) {
            inst.set_flag(InstructionFlags::RipRelative);
        }

        return true;
    }

    bool Disassembler::decode_modrm(DecodingContext& ctx) {
        if (ctx.offset >= ctx.max_size) return false;

        ctx.modrm = ctx.read_u8();
        ctx.has_modrm = true;

        if (ctx.modrm_mod() != 0x03 && ctx.modrm_rm() == 0x04) {
            return decode_sib(ctx);
        }

        return true;
    }

    bool Disassembler::decode_opcode(DecodingContext& ctx) {
        if (ctx.offset >= ctx.max_size) return false;

        ctx.opcode = ctx.read_u8();

        if (ctx.opcode == 0x0F) {
            if (ctx.offset >= ctx.max_size) return false;
            ctx.opcode = 0x0F00 | ctx.read_u8();
        }

        return true;
    }

    void Disassembler::decode_modrm_operands(DecodingContext& ctx, Instruction& inst) {
        if (!ctx.has_modrm) {
            decode_modrm(ctx);
            decode_displacement(ctx);
        }

        uint8_t op_size = ctx.operand_size;
        if ((ctx.opcode & 0x01) == 0) {
            op_size = 1;
        }

        bool direction = (ctx.opcode & 0x02) != 0;

        if (!direction) {

            auto dst = decode_modrm_operand(ctx, false);
            auto src = decode_modrm_operand(ctx, true);
            dst.size = op_size;
            src.size = op_size;
            inst.operands.push_back(dst);
            inst.operands.push_back(src);
        }
        else {

            auto dst = decode_modrm_operand(ctx, true);
            auto src = decode_modrm_operand(ctx, false);
            dst.size = op_size;
            src.size = op_size;
            inst.operands.push_back(dst);
            inst.operands.push_back(src);
        }

        handle_rip_relative(ctx, inst);
    }

    void Disassembler::decode_rel8(DecodingContext& ctx, Instruction& inst) {
        int8_t rel = static_cast<int8_t>(ctx.read_u8());
        Operand op;
        op.type = OperandType::Relative;
        op.immediate = ctx.address + ctx.offset + rel;
        op.size = 1;
        inst.operands.push_back(op);
        inst.set_flag(InstructionFlags::ControlFlow);
    }

    void Disassembler::decode_rel32(DecodingContext& ctx, Instruction& inst) {
        int32_t rel = static_cast<int32_t>(ctx.read_u32());
        Operand op;
        op.type = OperandType::Relative;
        op.immediate = ctx.address + ctx.offset + rel;
        op.size = 4;
        inst.operands.push_back(op);
    }

    void Disassembler::decode_imm8(DecodingContext& ctx, Instruction& inst) {
        Operand op;
        op.type = OperandType::Immediate;
        op.immediate = ctx.read_u8();
        op.size = 1;
        inst.operands.push_back(op);
    }

    void Disassembler::decode_imm16(DecodingContext& ctx, Instruction& inst) {
        Operand op;
        op.type = OperandType::Immediate;
        op.immediate = ctx.read_u16();
        op.size = 2;
        inst.operands.push_back(op);
    }

    void Disassembler::decode_imm32(DecodingContext& ctx, Instruction& inst) {
        Operand op;
        op.type = OperandType::Immediate;
        op.immediate = ctx.read_u32();
        op.size = 4;
        inst.operands.push_back(op);
    }

    void Disassembler::decode_register_in_opcode(DecodingContext& ctx, Instruction& inst, uint8_t reg) {
        Operand op;
        op.type = OperandType::Register;
        op.reg = decode_register_operand(reg, ctx.operand_size, ctx.prefixes.rex_b());
        op.size = ctx.operand_size;
        inst.operands.push_back(op);
    }

    void Disassembler::decode_al_imm8(DecodingContext& ctx, Instruction& inst) {
        Operand op1;
        op1.type = OperandType::Register;
        op1.reg = Register::AL;
        op1.size = 1;
        inst.operands.push_back(op1);

        decode_imm8(ctx, inst);
    }

    void Disassembler::decode_ax_imm(DecodingContext& ctx, Instruction& inst) {
        Operand op1;
        op1.type = OperandType::Register;
        op1.reg = ctx.operand_size == 8 ? Register::RAX :
            ctx.operand_size == 4 ? Register::EAX : Register::AX;
        op1.size = ctx.operand_size;
        inst.operands.push_back(op1);

        if (ctx.operand_size == 8) {
            decode_imm32(ctx, inst);
        }
        else {
            decode_imm32(ctx, inst);
        }
    }

    void Disassembler::decode_mov_reg_imm8(DecodingContext& ctx, Instruction& inst, uint8_t reg) {
        decode_register_in_opcode(ctx, inst, reg);
        decode_imm8(ctx, inst);
    }

    void Disassembler::decode_mov_reg_imm(DecodingContext& ctx, Instruction& inst, uint8_t reg) {
        decode_register_in_opcode(ctx, inst, reg);

        if (ctx.operand_size == 8 && ctx.prefixes.rex_w()) {

            Operand op;
            op.type = OperandType::Immediate;
            op.immediate = ctx.read_u64();
            op.size = 8;
            inst.operands.push_back(op);
        }
        else {
            decode_imm32(ctx, inst);
        }
    }

    void Disassembler::decode_mov_rm_imm(DecodingContext& ctx, Instruction& inst) {
        if (!ctx.has_modrm) {
            decode_modrm(ctx);
            decode_displacement(ctx);
        }

        auto dst = decode_modrm_operand(ctx, false);
        dst.size = (ctx.opcode == 0xC6) ? 1 : ctx.operand_size;
        inst.operands.push_back(dst);

        if (ctx.opcode == 0xC6) {
            decode_imm8(ctx, inst);
        }
        else {
            decode_imm32(ctx, inst);
        }

        handle_rip_relative(ctx, inst);
    }

    void Disassembler::decode_group1(DecodingContext& ctx, Instruction& inst) {
        if (!ctx.has_modrm) {
            decode_modrm(ctx);
            decode_displacement(ctx);
        }

        const char* mnemonics[] = { "add", "or", "adc", "sbb", "and", "sub", "xor", "cmp" };
        inst.mnemonic = mnemonics[ctx.modrm_reg()];

        auto dst = decode_modrm_operand(ctx, false);
        dst.size = (ctx.opcode == 0x80) ? 1 : ctx.operand_size;
        inst.operands.push_back(dst);

        if (ctx.opcode == 0x80 || ctx.opcode == 0x82) {
            decode_imm8(ctx, inst);
        }
        else if (ctx.opcode == 0x83) {

            int8_t imm = static_cast<int8_t>(ctx.read_u8());
            Operand op;
            op.type = OperandType::Immediate;
            op.imm_signed = imm;
            op.size = 1;
            inst.operands.push_back(op);
        }
        else {
            decode_imm32(ctx, inst);
        }

        handle_rip_relative(ctx, inst);
    }

    void Disassembler::decode_group3(DecodingContext& ctx, Instruction& inst) {
        if (!ctx.has_modrm) {
            decode_modrm(ctx);
            decode_displacement(ctx);
        }

        const char* mnemonics[] = { "test", "test", "not", "neg", "mul", "imul", "div", "idiv" };
        inst.mnemonic = mnemonics[ctx.modrm_reg()];

        auto op = decode_modrm_operand(ctx, false);
        op.size = (ctx.opcode == 0xF6) ? 1 : ctx.operand_size;
        inst.operands.push_back(op);

        if (ctx.modrm_reg() == 0 || ctx.modrm_reg() == 1) {
            if (ctx.opcode == 0xF6) {
                decode_imm8(ctx, inst);
            }
            else {
                decode_imm32(ctx, inst);
            }
        }

        handle_rip_relative(ctx, inst);
    }

    void Disassembler::decode_group4(DecodingContext& ctx, Instruction& inst) {
        if (!ctx.has_modrm) {
            decode_modrm(ctx);
            decode_displacement(ctx);
        }

        const char* mnemonics[] = { "inc", "dec", "???", "???", "???", "???", "???", "???" };
        inst.mnemonic = mnemonics[ctx.modrm_reg()];

        auto op = decode_modrm_operand(ctx, false);
        op.size = 1;
        inst.operands.push_back(op);

        handle_rip_relative(ctx, inst);
    }

    void Disassembler::decode_group5(DecodingContext& ctx, Instruction& inst) {
        if (!ctx.has_modrm) {
            decode_modrm(ctx);
            decode_displacement(ctx);
        }

        const char* mnemonics[] = { "inc", "dec", "call", "call", "jmp", "jmp", "push", "???" };
        inst.mnemonic = mnemonics[ctx.modrm_reg()];

        auto op = decode_modrm_operand(ctx, false);
        op.size = ctx.operand_size;
        inst.operands.push_back(op);

        if (ctx.modrm_reg() >= 2 && ctx.modrm_reg() <= 5) {
            inst.set_flag(InstructionFlags::ControlFlow);
            if (ctx.modrm_reg() == 2 || ctx.modrm_reg() == 3) {
                inst.set_flag(InstructionFlags::ModifiesStack);
            }
        }
        else if (ctx.modrm_reg() == 6) {
            inst.set_flag(InstructionFlags::ModifiesStack);
        }

        handle_rip_relative(ctx, inst);
    }

    void Disassembler::decode_operands(DecodingContext& ctx, Instruction& inst) {

        if (ctx.opcode < 0x100) {
            switch (ctx.opcode) {

            case 0x00: case 0x01: case 0x02: case 0x03:
                inst.mnemonic = "add";
                decode_modrm_operands(ctx, inst);
                break;
            case 0x04:
                inst.mnemonic = "add";
                decode_al_imm8(ctx, inst);
                break;
            case 0x05:
                inst.mnemonic = "add";
                decode_ax_imm(ctx, inst);
                break;

            case 0x08: case 0x09: case 0x0A: case 0x0B:
                inst.mnemonic = "or";
                decode_modrm_operands(ctx, inst);
                break;

            case 0x10: case 0x11: case 0x12: case 0x13:
                inst.mnemonic = "adc";
                decode_modrm_operands(ctx, inst);
                break;

            case 0x18: case 0x19: case 0x1A: case 0x1B:
                inst.mnemonic = "sbb";
                decode_modrm_operands(ctx, inst);
                break;

            case 0x20: case 0x21: case 0x22: case 0x23:
                inst.mnemonic = "and";
                decode_modrm_operands(ctx, inst);
                break;
            case 0x24:
                inst.mnemonic = "and";
                decode_al_imm8(ctx, inst);
                break;
            case 0x25:
                inst.mnemonic = "and";
                decode_ax_imm(ctx, inst);
                break;

            case 0x28: case 0x29: case 0x2A: case 0x2B:
                inst.mnemonic = "sub";
                decode_modrm_operands(ctx, inst);
                break;
            case 0x2C:
                inst.mnemonic = "sub";
                decode_al_imm8(ctx, inst);
                break;
            case 0x2D:
                inst.mnemonic = "sub";
                decode_ax_imm(ctx, inst);
                break;

            case 0x30: case 0x31: case 0x32: case 0x33:
                inst.mnemonic = "xor";
                decode_modrm_operands(ctx, inst);
                break;

            case 0x38: case 0x39: case 0x3A: case 0x3B:
                inst.mnemonic = "cmp";
                decode_modrm_operands(ctx, inst);
                break;
            case 0x3C:
                inst.mnemonic = "cmp";
                decode_al_imm8(ctx, inst);
                break;
            case 0x3D:
                inst.mnemonic = "cmp";
                decode_ax_imm(ctx, inst);
                break;

            case 0x50: case 0x51: case 0x52: case 0x53:
            case 0x54: case 0x55: case 0x56: case 0x57:
                inst.mnemonic = "push";
                decode_register_in_opcode(ctx, inst, ctx.opcode - 0x50);
                inst.set_flag(InstructionFlags::ModifiesStack);
                break;

            case 0x58: case 0x59: case 0x5A: case 0x5B:
            case 0x5C: case 0x5D: case 0x5E: case 0x5F:
                inst.mnemonic = "pop";
                decode_register_in_opcode(ctx, inst, ctx.opcode - 0x58);
                inst.set_flag(InstructionFlags::ModifiesStack);
                break;

            case 0x70: inst.mnemonic = "jo"; decode_rel8(ctx, inst); break;
            case 0x71: inst.mnemonic = "jno"; decode_rel8(ctx, inst); break;
            case 0x72: inst.mnemonic = "jb"; decode_rel8(ctx, inst); break;
            case 0x73: inst.mnemonic = "jnb"; decode_rel8(ctx, inst); break;
            case 0x74: inst.mnemonic = "je"; decode_rel8(ctx, inst); break;
            case 0x75: inst.mnemonic = "jne"; decode_rel8(ctx, inst); break;
            case 0x76: inst.mnemonic = "jbe"; decode_rel8(ctx, inst); break;
            case 0x77: inst.mnemonic = "ja"; decode_rel8(ctx, inst); break;
            case 0x78: inst.mnemonic = "js"; decode_rel8(ctx, inst); break;
            case 0x79: inst.mnemonic = "jns"; decode_rel8(ctx, inst); break;
            case 0x7A: inst.mnemonic = "jp"; decode_rel8(ctx, inst); break;
            case 0x7B: inst.mnemonic = "jnp"; decode_rel8(ctx, inst); break;
            case 0x7C: inst.mnemonic = "jl"; decode_rel8(ctx, inst); break;
            case 0x7D: inst.mnemonic = "jge"; decode_rel8(ctx, inst); break;
            case 0x7E: inst.mnemonic = "jle"; decode_rel8(ctx, inst); break;
            case 0x7F: inst.mnemonic = "jg"; decode_rel8(ctx, inst); break;

            case 0x80: case 0x81: case 0x82: case 0x83:
                decode_group1(ctx, inst);
                break;

            case 0x84: case 0x85:
                inst.mnemonic = "test";
                decode_modrm_operands(ctx, inst);
                break;

            case 0x88: case 0x89: case 0x8A: case 0x8B:
                inst.mnemonic = "mov";
                decode_modrm_operands(ctx, inst);
                break;

            case 0x8D:
                inst.mnemonic = "lea";
                decode_modrm_operands(ctx, inst);
                break;

            case 0x90:
                inst.mnemonic = "nop";
                break;

            case 0xB0: case 0xB1: case 0xB2: case 0xB3:
            case 0xB4: case 0xB5: case 0xB6: case 0xB7:
                inst.mnemonic = "mov";
                decode_mov_reg_imm8(ctx, inst, ctx.opcode - 0xB0);
                break;

            case 0xB8: case 0xB9: case 0xBA: case 0xBB:
            case 0xBC: case 0xBD: case 0xBE: case 0xBF:
                inst.mnemonic = "mov";
                decode_mov_reg_imm(ctx, inst, ctx.opcode - 0xB8);
                break;

            case 0xC2:
                inst.mnemonic = "ret";
                decode_imm16(ctx, inst);
                inst.set_flag(InstructionFlags::ControlFlow | InstructionFlags::ModifiesStack);
                break;

            case 0xC3:
                inst.mnemonic = "ret";
                inst.set_flag(InstructionFlags::ControlFlow | InstructionFlags::ModifiesStack);
                break;

            case 0xC6: case 0xC7:
                inst.mnemonic = "mov";
                decode_mov_rm_imm(ctx, inst);
                break;

            case 0xCC:
                inst.mnemonic = "int3";
                break;

            case 0xCD:
                inst.mnemonic = "int";
                decode_imm8(ctx, inst);
                break;

            case 0xE8:
                inst.mnemonic = "call";
                decode_rel32(ctx, inst);
                inst.set_flag(InstructionFlags::ControlFlow | InstructionFlags::ModifiesStack);
                break;

            case 0xE9:
                inst.mnemonic = "jmp";
                decode_rel32(ctx, inst);
                inst.set_flag(InstructionFlags::ControlFlow);
                break;

            case 0xEB:
                inst.mnemonic = "jmp";
                decode_rel8(ctx, inst);
                inst.set_flag(InstructionFlags::ControlFlow);
                break;

            case 0xF6: case 0xF7:
                decode_group3(ctx, inst);
                break;

            case 0xFE:
                decode_group4(ctx, inst);
                break;

            case 0xFF:
                decode_group5(ctx, inst);
                break;

            default:

                inst.mnemonic = "db";
                Operand op;
                op.type = OperandType::Immediate;
                op.immediate = ctx.opcode;
                op.size = 1;
                inst.operands.push_back(op);
                break;
            }
        }

        else if ((ctx.opcode & 0xFF00) == 0x0F00) {
            uint8_t second_byte = ctx.opcode & 0xFF;

            if (second_byte >= 0x80 && second_byte <= 0x8F) {
                const char* jcc_names[] = {
                    "jo", "jno", "jb", "jnb", "je", "jne", "jbe", "ja",
                    "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"
                };
                inst.mnemonic = jcc_names[second_byte - 0x80];
                decode_rel32(ctx, inst);
                inst.set_flag(InstructionFlags::ControlFlow | InstructionFlags::Conditional);
            }
            else {

                inst.mnemonic = "db";
                Operand op;
                op.type = OperandType::Immediate;
                op.immediate = 0x0F;
                op.size = 1;
                inst.operands.push_back(op);
            }
        }
    }

    bool Disassembler::decode_displacement(DecodingContext& ctx) {
        if (!ctx.has_modrm) return true;

        uint8_t mod = ctx.modrm_mod();
        uint8_t rm = ctx.modrm_rm();

        if (mod == 0x00 && rm == 0x05) {
            ctx.displacement = static_cast<int32_t>(ctx.read_u32());
            return true;
        }

        if (mod == 0x01) {
            ctx.displacement = static_cast<int8_t>(ctx.read_u8());
        }
        else if (mod == 0x02) {
            ctx.displacement = static_cast<int32_t>(ctx.read_u32());
        }
        else if (mod == 0x00 && ctx.has_sib && ctx.sib_base() == 0x05) {
            ctx.displacement = static_cast<int32_t>(ctx.read_u32());
        }

        return true;
    }

    bool Disassembler::decode_immediate(DecodingContext& ctx) {

        if (ctx.opcode == 0xE8 || ctx.opcode == 0xE9) {
            ctx.immediate = static_cast<int32_t>(ctx.read_u32());
            return true;
        }

        if (ctx.opcode == 0xEB) {
            ctx.immediate = static_cast<int8_t>(ctx.read_u8());
            return true;
        }

        if (ctx.opcode == 0xC2) {
            ctx.immediate = ctx.read_u16();
            return true;
        }

        return true;

    }

    Operand Disassembler::decode_modrm_operand(DecodingContext& ctx, bool is_reg_field) {
        Operand op;

        if (is_reg_field) {

            op.type = OperandType::Register;
            op.reg = decode_register_operand(ctx.modrm_reg(), ctx.operand_size, ctx.prefixes.rex_r());
            op.size = ctx.operand_size;
            return op;
        }

        uint8_t mod = ctx.modrm_mod();
        uint8_t rm = ctx.modrm_rm();

        if (mod == 0x03) {

            op.type = OperandType::Register;
            op.reg = decode_register_operand(rm, ctx.operand_size, ctx.prefixes.rex_b());
            op.size = ctx.operand_size;
        }
        else {

            op.type = OperandType::Memory;
            op.size = ctx.operand_size;
            op.mem_size = static_cast<MemorySize>(ctx.operand_size);

            if (mod == 0x00 && rm == 0x05) {
                op.base = Register::RIP;
                op.displacement = ctx.displacement;
                op.is_rip_relative = true;
            }
            else if (ctx.has_sib) {

                uint8_t scale = ctx.sib_scale();
                uint8_t index = ctx.sib_index();
                uint8_t base = ctx.sib_base();

                if (base != 0x05 || mod != 0x00) {
                    op.base = decode_register_operand(base, 8, ctx.prefixes.rex_b());
                }

                if (index != 0x04) {
                    op.index = decode_register_operand(index, 8, ctx.prefixes.rex_x());
                    op.scale = 1 << scale;
                }

                op.displacement = ctx.displacement;
            }
            else {

                op.base = decode_register_operand(rm, 8, ctx.prefixes.rex_b());
                op.displacement = ctx.displacement;
            }
        }

        return op;
    }

    void Disassembler::handle_rip_relative(DecodingContext& ctx, Instruction& inst) {
        for (auto& op : inst.operands) {
            if (op.is_rip_relative) {
                inst.is_rip_relative = true;
                inst.rip_target = ctx.address + inst.length + op.displacement;
                op.immediate = inst.rip_target;
            }
        }
    }

    bool Disassembler::decode_sib(DecodingContext& ctx) {
        if (ctx.offset >= ctx.max_size) return false;

        ctx.sib = ctx.read_u8();
        ctx.has_sib = true;
        return true;

    }

    void Disassembler::add_symbol(uintptr_t address, const std::string& name) {
        symbols[address] = name;
    }

    std::optional<std::string> Disassembler::resolve_symbol(uintptr_t address) const {
        auto it = symbols.find(address);
        if (it != symbols.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    std::vector<Instruction> Disassembler::disassemble_range(uintptr_t start, uintptr_t end) {
        std::vector<Instruction> instructions;
        uintptr_t current = start;

        while (current < end) {
            Instruction inst = disassemble(current);
            if (inst.length == 0) break;

            instructions.push_back(inst);
            current += inst.length;
        }

        return instructions;
    }

    std::vector<Instruction> Disassembler::disassemble_until(uintptr_t start,
        std::function<bool(const Instruction&)> predicate) {
        std::vector<Instruction> instructions;
        uintptr_t current = start;

        while (true) {
            Instruction inst = disassemble(current);
            if (inst.length == 0) break;

            instructions.push_back(inst);

            if (predicate(inst)) {
                break;
            }

            current += inst.length;
        }

        return instructions;
    }

    Disassembler::Disassembler(ProcessInfo* proc_info, const DisassemblerConfig& config)
        : process_info(proc_info), config(config) {
    }

    Register Disassembler::decode_register_operand(uint8_t reg, uint8_t size, bool rex_ext) {
        uint8_t actual_reg = reg & 0x07;
        if (rex_ext) {
            actual_reg += 8;
        }

        switch (size) {
        case 1:
            if (actual_reg < 16) {
                return static_cast<Register>(static_cast<uint8_t>(Register::AL) + actual_reg);
            }
            break;
        case 2:
            if (actual_reg < 16) {
                return static_cast<Register>(static_cast<uint8_t>(Register::AX) + actual_reg);
            }
            break;
        case 4:
            if (actual_reg < 16) {
                return static_cast<Register>(static_cast<uint8_t>(Register::EAX) + actual_reg);
            }
            break;
        case 8:
            if (actual_reg < 16) {
                return static_cast<Register>(static_cast<uint8_t>(Register::RAX) + actual_reg);
            }
            break;
        }

        return Register::NONE;
    }

    bool Disassembler::decode_prefixes(DecodingContext& ctx) {
        bool found_prefix = true;

        while (found_prefix && ctx.offset < ctx.max_size) {
            uint8_t byte = ctx.data[ctx.offset];
            found_prefix = true;

            switch (byte) {
            case 0x66:
                ctx.prefixes.operand_size = true;
                ctx.operand_size = 2;
                ctx.offset++;
                break;
            case 0x67:
                ctx.prefixes.address_size = true;
                ctx.address_size = 4;
                ctx.offset++;
                break;
            default:

                if ((byte & 0xF0) == 0x40) {
                    ctx.prefixes.rex = byte;
                    if (ctx.prefixes.rex_w()) {
                        ctx.operand_size = 8;
                    }
                    ctx.offset++;
                }
                else {
                    found_prefix = false;
                }
                break;
            }
        }

        return true;
    }

    Instruction Disassembler::disassemble(uintptr_t address) {
        Instruction inst;
        inst.address = address;

        uint8_t buffer[15];
        size_t bytes_read = 0;

        for (size_t i = 0; i < sizeof(buffer); ++i) {
            if (process_info->read_memory(address + i, &buffer[i], 1)) {
                bytes_read++;
            }
            else {
                break;
            }
        }

        if (bytes_read == 0) {
            inst.mnemonic = "???";
            inst.length = 1;
            return inst;
        }

        DecodingContext ctx;
        ctx.data = buffer;
        ctx.max_size = bytes_read;
        ctx.address = address;
        ctx.offset = 0;

        decode_prefixes(ctx);

        uint8_t opcode = ctx.read_u8();

        switch (opcode) {
        case 0x90:
            inst.mnemonic = "nop";
            break;

        case 0xC3:
            inst.mnemonic = "ret";
            inst.set_flag(InstructionFlags::ControlFlow | InstructionFlags::ModifiesStack);
            break;

        case 0xE8:
        {
            inst.mnemonic = "call";
            uint32_t rel32 = ctx.read_u32();
            Operand op;
            op.type = OperandType::Relative;
            op.immediate = ctx.address + 5 + static_cast<int32_t>(rel32);
            inst.operands.push_back(op);
            inst.set_flag(InstructionFlags::ControlFlow | InstructionFlags::ModifiesStack);
        }
        break;

        case 0xE9:
        {
            inst.mnemonic = "jmp";
            uint32_t rel32 = ctx.read_u32();
            Operand op;
            op.type = OperandType::Relative;
            op.immediate = ctx.address + 5 + static_cast<int32_t>(rel32);
            inst.operands.push_back(op);
            inst.set_flag(InstructionFlags::ControlFlow);
        }
        break;

        default:
            inst.mnemonic = "db";
            Operand op;
            op.type = OperandType::Immediate;
            op.immediate = opcode;
            inst.operands.push_back(op);
            break;
        }

        inst.length = ctx.offset;
        inst.bytes.assign(buffer, buffer + inst.length);

        return inst;
    }

    std::vector<Instruction> Disassembler::disassemble_count(uintptr_t start, size_t count) {
        std::vector<Instruction> instructions;
        uintptr_t current = start;

        for (size_t i = 0; i < count; ++i) {
            Instruction inst = disassemble(current);
            if (inst.length == 0) break;

            instructions.push_back(inst);
            current += inst.length;
        }

        return instructions;
    }

    PatternScanner::PatternScanner(ProcessInfo* proc_info, const PatternConfig& config)
        : process_info(proc_info), config(config) {
    }

    PatternScanner::Pattern PatternScanner::parse_pattern(const std::string& pattern) {
        Pattern result;
        std::istringstream iss(pattern);
        std::string byte_str;

        while (iss >> byte_str) {
            if (byte_str == "??" || byte_str == "?") {
                result.bytes.push_back(0);
                result.mask.push_back(false);
            }
            else {
                result.bytes.push_back(static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16)));
                result.mask.push_back(true);
            }
        }

        return result;
    }

    bool PatternScanner::match_pattern(const uint8_t* data, const Pattern& pattern) {
        for (size_t i = 0; i < pattern.bytes.size(); ++i) {
            if (pattern.mask[i] && data[i] != pattern.bytes[i]) {
                return false;
            }
        }
        return true;
    }

    std::vector<uintptr_t> PatternScanner::scan_module(const std::string& pattern, const std::string& module_name) {
        std::vector<uintptr_t> results;
        Pattern parsed = parse_pattern(pattern);

        if (parsed.bytes.empty()) {
            return results;
        }

        auto regions = process_info->enumerate_regions();

        for (const auto& region : regions) {
            if (region.is_executable()) {
                auto region_results = scan_region(region, parsed);
                results.insert(results.end(), region_results.begin(), region_results.end());

                if (config.max_results > 0 && results.size() >= config.max_results) {
                    break;
                }
            }
        }

        return results;
    }

    std::vector<uintptr_t> PatternScanner::scan_region(const MemoryRegion& region, const Pattern& pattern) {
        std::vector<uintptr_t> results;

        if (pattern.bytes.empty()) {
            return results;
        }

        if (!region.is_readable()) {
            return results;
        }

        const size_t MAX_SCAN_SIZE = 1000 * 1024 * 1024;
        size_t scan_size = std::min(region.size, MAX_SCAN_SIZE);

        if (scan_size < pattern.bytes.size()) {
            return results;
        }

        std::vector<uint8_t> buffer(scan_size);

        if (!process_info->read_memory(region.base, buffer.data(), scan_size)) {
            return results;
        }

        size_t scan_end = scan_size - pattern.bytes.size() + 1;

        for (size_t i = 0; i < scan_end; i += config.alignment) {
            if (match_pattern(&buffer[i], pattern)) {
                results.push_back(region.base + i);

                if (config.max_results > 0 && results.size() >= config.max_results) {
                    break;
                }
            }
        }

        return results;
    }

    std::vector<uintptr_t> PatternScanner::scan(const std::string& pattern, uintptr_t start, uintptr_t end) {
        std::vector<uintptr_t> results;
        Pattern parsed = parse_pattern(pattern);

        if (parsed.bytes.empty()) {
            return results;
        }

        auto regions = process_info->enumerate_regions();

        for (const auto& region : regions) {

            if (config.scan_executable_only && !region.is_executable()) {
                continue;
            }

            if (start != 0 && region.base + region.size <= start) {
                continue;
            }
            if (end != 0 && region.base >= end) {
                continue;
            }

            auto region_results = scan_region(region, parsed);
            results.insert(results.end(), region_results.begin(), region_results.end());

            if (config.max_results > 0 && results.size() >= config.max_results) {
                break;
            }
        }

        return results;
    }

    std::vector<uintptr_t> PatternScanner::scan_all_modules(const std::string& pattern) {
        std::vector<uintptr_t> results;
        Pattern parsed = parse_pattern(pattern);

        if (parsed.bytes.empty()) {
            return results;
        }

        auto modules = process_info->enumerate_modules();

        for (const auto& module : modules) {
            auto module_results = scan(pattern, module.base, module.base + module.size);
            results.insert(results.end(), module_results.begin(), module_results.end());

            if (config.max_results > 0 && results.size() >= config.max_results) {
                break;
            }
        }

        return results;
    }

    std::vector<uintptr_t> PatternScanner::scan_string(const std::string& str, bool unicode,
        uintptr_t start, uintptr_t end) {
        std::string pattern;

        if (unicode) {
            for (char c : str) {
                std::stringstream ss;
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<uint8_t>(c) << " 00 ";
                pattern += ss.str();
            }
            pattern += "00 00";
        }
        else {
            for (char c : str) {
                std::stringstream ss;
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<uint8_t>(c) << " ";
                pattern += ss.str();
            }
            pattern += "00";
        }

        return scan(pattern, start, end);
    }

    bool PatternScanner::is_call_instruction(const uint8_t* bytes, uintptr_t& target, uintptr_t address) {
        if (bytes[0] == 0xE8) {
            int32_t offset = *reinterpret_cast<const int32_t*>(&bytes[1]);
            target = address + 5 + offset;
            return true;
        }

        if (bytes[0] == 0xFF && (bytes[1] & 0x38) == 0x10) {

            return false;
        }

        return false;
    }

    bool PatternScanner::is_jump_instruction(const uint8_t* bytes, uintptr_t& target, uintptr_t address) {
        if (bytes[0] == 0xE9) {
            int32_t offset = *reinterpret_cast<const int32_t*>(&bytes[1]);
            target = address + 5 + offset;
            return true;
        }

        if (bytes[0] == 0xEB) {
            int8_t offset = static_cast<int8_t>(bytes[1]);
            target = address + 2 + offset;
            return true;
        }

        if (bytes[0] == 0x0F && (bytes[1] & 0xF0) == 0x80) {
            int32_t offset = *reinterpret_cast<const int32_t*>(&bytes[2]);
            target = address + 6 + offset;
            return true;
        }

        return false;
    }

    std::vector<uintptr_t> PatternScanner::scan_xrefs(uintptr_t target, uintptr_t start, uintptr_t end) {
        std::vector<uintptr_t> results;

        auto regions = process_info->enumerate_regions();

        for (const auto& region : regions) {
            if (!region.is_executable()) continue;

            if (start != 0 && region.base + region.size <= start) continue;
            if (end != 0 && region.base >= end) continue;

            std::vector<uint8_t> buffer(region.size);
            if (!process_info->read_memory(region.base, buffer.data(), region.size)) {
                continue;
            }

            for (size_t i = 0; i < region.size - 5; ++i) {
                uintptr_t ref_target = 0;

                if (is_call_instruction(&buffer[i], ref_target, region.base + i) ||
                    is_jump_instruction(&buffer[i], ref_target, region.base + i)) {
                    if (ref_target == target) {
                        results.push_back(region.base + i);
                    }
                }
            }
        }

        return results;
    }

    std::vector<uintptr_t> PatternScanner::scan_calls(uintptr_t target, uintptr_t start, uintptr_t end) {
        std::vector<uintptr_t> results;

        auto all_xrefs = scan_xrefs(target, start, end);

        for (uintptr_t xref : all_xrefs) {
            uint8_t opcode;
            if (process_info->read_memory(xref, &opcode, 1) && opcode == 0xE8) {
                results.push_back(xref);
            }
        }

        return results;
    }

    std::string PatternScanner::generate_pattern(const uint8_t* bytes, size_t length, const bool* wildcards) {
        std::stringstream ss;

        for (size_t i = 0; i < length; ++i) {
            if (i > 0) ss << " ";

            if (wildcards && wildcards[i]) {
                ss << "??";
            }
            else {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);
            }
        }

        return ss.str();
    }

    namespace Hooks {

        bool place_jmp(uintptr_t from, uintptr_t to, ProcessInfo* proc_info) {

            int64_t offset = to - (from + 5);

            if (offset > INT32_MAX || offset < INT32_MIN) {

                uint8_t abs_jmp[] = {
                    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0xFF, 0xE0
                };

                *reinterpret_cast<uint64_t*>(&abs_jmp[2]) = to;

                DWORD old_protect = Memory::set_protection(from, sizeof(abs_jmp), PAGE_EXECUTE_READWRITE, proc_info);
                bool result = proc_info->write_memory(from, abs_jmp, sizeof(abs_jmp));
                Memory::set_protection(from, sizeof(abs_jmp), old_protect, proc_info);

                return result;
            }
            else {

                uint8_t rel_jmp[] = {
                    0xE9, 0x00, 0x00, 0x00, 0x00
                };

                *reinterpret_cast<int32_t*>(&rel_jmp[1]) = static_cast<int32_t>(offset);

                DWORD old_protect = Memory::set_protection(from, sizeof(rel_jmp), PAGE_EXECUTE_READWRITE, proc_info);
                bool result = proc_info->write_memory(from, rel_jmp, sizeof(rel_jmp));
                Memory::set_protection(from, sizeof(rel_jmp), old_protect, proc_info);

                return result;
            }
        }

        bool place_call(uintptr_t from, uintptr_t to, ProcessInfo* proc_info) {

            int64_t offset = to - (from + 5);

            if (offset > INT32_MAX || offset < INT32_MIN) {

                uint8_t abs_call[] = {
                    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0xFF, 0xD0
                };

                *reinterpret_cast<uint64_t*>(&abs_call[2]) = to;

                DWORD old_protect = Memory::set_protection(from, sizeof(abs_call), PAGE_EXECUTE_READWRITE, proc_info);
                bool result = proc_info->write_memory(from, abs_call, sizeof(abs_call));
                Memory::set_protection(from, sizeof(abs_call), old_protect, proc_info);

                return result;
            }
            else {

                uint8_t rel_call[] = {
                    0xE8, 0x00, 0x00, 0x00, 0x00
                };

                *reinterpret_cast<int32_t*>(&rel_call[1]) = static_cast<int32_t>(offset);

                DWORD old_protect = Memory::set_protection(from, sizeof(rel_call), PAGE_EXECUTE_READWRITE, proc_info);
                bool result = proc_info->write_memory(from, rel_call, sizeof(rel_call));
                Memory::set_protection(from, sizeof(rel_call), old_protect, proc_info);

                return result;
            }
        }

        bool place_push_ret(uintptr_t from, uintptr_t to, ProcessInfo* proc_info) {

            uint8_t push_ret[] = {
                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x50,
                0xC3
            };

            *reinterpret_cast<uint64_t*>(&push_ret[2]) = to;

            DWORD old_protect = Memory::set_protection(from, sizeof(push_ret), PAGE_EXECUTE_READWRITE, proc_info);
            bool result = proc_info->write_memory(from, push_ret, sizeof(push_ret));
            Memory::set_protection(from, sizeof(push_ret), old_protect, proc_info);

            return result;
        }

        bool place_nop(uintptr_t address, size_t count, ProcessInfo* proc_info) {
            if (count == 0) return true;

            std::vector<uint8_t> nops(count, 0x90);

            DWORD old_protect = Memory::set_protection(address, count, PAGE_EXECUTE_READWRITE, proc_info);
            bool result = proc_info->write_memory(address, nops.data(), count);
            Memory::set_protection(address, count, old_protect, proc_info);

            return result;
        }

        bool place_nop_sled(uintptr_t address, size_t count, ProcessInfo* proc_info) {

            std::vector<uint8_t> nop_buffer;
            size_t remaining = count;

            const uint8_t nop_sequences[][15] = {
                {0x90},
                {0x66, 0x90},
                {0x0F, 0x1F, 0x00},
                {0x0F, 0x1F, 0x40, 0x00},
                {0x0F, 0x1F, 0x44, 0x00, 0x00},
                {0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00},
                {0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00},
                {0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},
                {0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},
            };

            while (remaining > 0) {
                size_t nop_size = std::min(remaining, size_t(9));
                if (nop_size == 0) break;

                const uint8_t* nop_seq = nop_sequences[nop_size - 1];
                nop_buffer.insert(nop_buffer.end(), nop_seq, nop_seq + nop_size);
                remaining -= nop_size;
            }

            DWORD old_protect = Memory::set_protection(address, count, PAGE_EXECUTE_READWRITE, proc_info);
            bool result = proc_info->write_memory(address, nop_buffer.data(), count);
            Memory::set_protection(address, count, old_protect, proc_info);

            return result;
        }

        bool place_hook(uintptr_t from, uintptr_t to, HookType type, ProcessInfo* proc_info) {
            switch (type) {
            case HookType::JMP:
                return place_jmp(from, to, proc_info);
            case HookType::CALL:
                return place_call(from, to, proc_info);
            case HookType::PUSH_RET:
                return place_push_ret(from, to, proc_info);
            case HookType::NOP_SLIDE:
                return place_nop(from, 5, proc_info);
            default:
                return false;
            }
        }

        std::optional<TrampolineInfo> create_trampoline(uintptr_t from, uintptr_t to, ProcessInfo* proc_info) {
            TrampolineInfo info;
            info.original_address = from;
            info.hook_address = to;

            info.hook_size = Memory::calculate_hook_size(from, 5, proc_info);
            if (info.hook_size == 0) {
                return std::nullopt;
            }

            info.original_bytes.resize(info.hook_size);
            if (!proc_info->read_memory(from, info.original_bytes.data(), info.hook_size)) {
                return std::nullopt;
            }

            info.trampoline_address = proc_info->allocate(info.hook_size + 14);
            if (!info.trampoline_address) {
                return std::nullopt;
            }

            if (!proc_info->write_memory(info.trampoline_address, info.original_bytes.data(), info.hook_size)) {
                proc_info->free(info.trampoline_address);
                return std::nullopt;
            }

            if (!place_jmp(info.trampoline_address + info.hook_size, from + info.hook_size, proc_info)) {
                proc_info->free(info.trampoline_address);
                return std::nullopt;
            }

            if (!place_jmp(from, to, proc_info)) {
                proc_info->free(info.trampoline_address);
                return std::nullopt;
            }

            return info;
        }

        bool remove_trampoline(const TrampolineInfo& info, ProcessInfo* proc_info) {

            DWORD old_protect = Memory::set_protection(info.original_address, info.hook_size,
                PAGE_EXECUTE_READWRITE, proc_info);
            bool result = proc_info->write_memory(info.original_address,
                info.original_bytes.data(), info.hook_size);
            Memory::set_protection(info.original_address, info.hook_size, old_protect, proc_info);

            if (info.trampoline_address) {
                proc_info->free(info.trampoline_address);
            }

            return result;
        }

        Detour::Detour(uintptr_t target, uintptr_t hook, ProcessInfo* proc_info)
            : proc_info(proc_info), target_address(target), hook_address(hook) {
        }

        Detour::~Detour() {
            if (installed) {
                uninstall();
            }
        }

        bool Detour::install() {
            if (installed) return true;

            auto trampoline = create_trampoline(target_address, hook_address, proc_info);
            if (!trampoline) {
                return false;
            }

            trampoline_address = trampoline->trampoline_address;
            original_bytes = trampoline->original_bytes;
            hook_size = trampoline->hook_size;
            installed = true;

            return true;
        }

        bool Detour::uninstall() {
            if (!installed) return true;

            TrampolineInfo info;
            info.original_address = target_address;
            info.trampoline_address = trampoline_address;
            info.original_bytes = original_bytes;
            info.hook_size = hook_size;

            if (remove_trampoline(info, proc_info)) {
                installed = false;
                return true;
            }

            return false;
        }

    }

    namespace Memory {

        DWORD set_protection(uintptr_t address, size_t size, DWORD new_protect, ProcessInfo* proc_info) {
            DWORD old_protect = 0;

            if (proc_info->is_external()) {
                VirtualProtectEx(proc_info->get_handle(), reinterpret_cast<LPVOID>(address),
                    size, new_protect, &old_protect);
            }
            else {
                VirtualProtect(reinterpret_cast<LPVOID>(address), size, new_protect, &old_protect);
            }

            return old_protect;
        }

        std::vector<uint8_t> pattern_to_bytes(const std::string& pattern) {
            std::vector<uint8_t> bytes;
            std::istringstream iss(pattern);
            std::string byte_str;

            while (iss >> byte_str) {
                if (byte_str == "??" || byte_str == "?") {
                    bytes.push_back(0);
                }
                else {
                    bytes.push_back(static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16)));
                }
            }

            return bytes;
        }

        std::string bytes_to_pattern(const uint8_t* bytes, size_t length) {
            std::stringstream ss;

            for (size_t i = 0; i < length; ++i) {
                if (i > 0) ss << " ";
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);
            }

            return ss.str();
        }

        size_t get_instruction_length(uintptr_t address, ProcessInfo* proc_info) {
            Disassembler disasm(proc_info);
            auto inst = disasm.disassemble(address);
            return inst.length;
        }

        size_t calculate_hook_size(uintptr_t address, size_t minimum_size, ProcessInfo* proc_info) {
            Disassembler disasm(proc_info);
            size_t total_size = 0;
            uintptr_t current = address;

            while (total_size < minimum_size) {
                auto inst = disasm.disassemble(current);
                if (inst.length == 0) {
                    return 0;
                }

                total_size += inst.length;
                current += inst.length;
            }

            return total_size;
        }

        uintptr_t resolve_rip_relative(uintptr_t instruction_address, int32_t offset, size_t instruction_length) {
            return instruction_address + instruction_length + offset;
        }

        int32_t calculate_relative_offset(uintptr_t from, uintptr_t to, size_t instruction_length) {
            int64_t offset = static_cast<int64_t>(to) - static_cast<int64_t>(from) - instruction_length;

            if (offset > INT32_MAX || offset < INT32_MIN) {
                return 0;
            }

            return static_cast<int32_t>(offset);
        }

        std::string read_string(uintptr_t address, ProcessInfo* proc_info, size_t max_length) {
            std::string result;
            char ch;

            for (size_t i = 0; i < max_length; ++i) {
                if (!proc_info->read_memory(address + i, &ch, 1) || ch == '\0') {
                    break;
                }
                result += ch;
            }

            return result;
        }

        std::wstring read_wstring(uintptr_t address, ProcessInfo* proc_info, size_t max_length) {
            std::wstring result;
            wchar_t ch;

            for (size_t i = 0; i < max_length; ++i) {
                if (!proc_info->read_memory(address + i * sizeof(wchar_t), &ch, sizeof(wchar_t)) || ch == L'\0') {
                    break;
                }
                result += ch;
            }

            return result;
        }

    }

    namespace Analysis {

        bool is_function_prologue(uintptr_t address, ProcessInfo* proc_info) {

            const std::vector<std::string> prologue_patterns = {
                "48 89 5C 24 ??",
                "48 83 EC ??",
                "48 8B EC",
                "55 48 8B EC",
                "40 53",
                "48 8D 6C 24 ??",
                "48 81 EC ?? ?? ?? ??",
            };

            PatternScanner scanner(proc_info);

            for (const auto& pattern : prologue_patterns) {
                auto results = scanner.scan(pattern, address, address + 16);
                if (!results.empty() && results[0] == address) {
                    return true;
                }
            }

            return false;
        }

        bool is_function_epilogue(uintptr_t address, ProcessInfo* proc_info) {

            const std::vector<std::string> epilogue_patterns = {
                "48 8B 5C 24 ?? 48 83 C4 ?? C3",
                "48 83 C4 ?? C3",
                "5D C3",
                "48 8B E5 5D C3",
                "C3",
                "C2 ?? ??",
            };

            PatternScanner scanner(proc_info);

            for (const auto& pattern : epilogue_patterns) {
                auto results = scanner.scan(pattern, address, address + 16);
                if (!results.empty() && results[0] == address) {
                    return true;
                }
            }

            return false;
        }

        std::optional<FunctionInfo> analyze_function(uintptr_t address, ProcessInfo* proc_info) {
            FunctionInfo info;
            info.start = address;

            info.has_prologue = is_function_prologue(address, proc_info);

            Disassembler disasm(proc_info);
            uintptr_t current = address;
            size_t max_size = 0x10000;
            bool found_end = false;

            while (current - address < max_size && !found_end) {
                auto inst = disasm.disassemble(current);

                if (inst.length == 0) {
                    break;
                }

                if (inst.is_call()) {
                    info.calls.push_back(current);
                }

                if (inst.is_jump() && !inst.is_conditional()) {
                    info.jumps.push_back(current);

                    auto target = inst.get_branch_target();
                    if (target && (target < address || target > current + 0x1000)) {
                        found_end = true;
                    }
                }

                if (inst.is_return()) {
                    info.end = current + inst.length;
                    info.has_epilogue = true;
                    found_end = true;
                }

                if (inst.mnemonic == "int3" || inst.mnemonic == "???") {
                    info.end = current;
                    found_end = true;
                }

                current += inst.length;
            }

            if (!found_end) {
                info.end = current;
            }

            return info;
        }

        std::vector<uintptr_t> find_function_calls(uintptr_t function_start, ProcessInfo* proc_info) {
            std::vector<uintptr_t> calls;

            auto func_info = analyze_function(function_start, proc_info);
            if (func_info) {
                Disassembler disasm(proc_info);

                for (uintptr_t call_addr : func_info->calls) {
                    auto inst = disasm.disassemble(call_addr);
                    auto target = inst.get_branch_target();
                    if (target) {
                        calls.push_back(target);
                    }
                }
            }

            return calls;
        }

        std::vector<uintptr_t> find_function_xrefs(uintptr_t function_address, ProcessInfo* proc_info) {
            PatternScanner scanner(proc_info);
            return scanner.scan_xrefs(function_address);
        }

        std::vector<uintptr_t> trace_execution_flow(uintptr_t start, ProcessInfo* proc_info) {
            std::vector<uintptr_t> flow;
            std::set<uintptr_t> visited;
            std::queue<uintptr_t> to_visit;

            to_visit.push(start);
            Disassembler disasm(proc_info);

            size_t max_instructions = 10000;

            while (!to_visit.empty() && flow.size() < max_instructions) {
                uintptr_t current = to_visit.front();
                to_visit.pop();

                if (visited.count(current)) {
                    continue;
                }

                visited.insert(current);
                flow.push_back(current);

                auto inst = disasm.disassemble(current);

                if (inst.length == 0) {
                    continue;
                }

                if ((!inst.is_jump() || inst.is_conditional()) && visited.count(current + inst.length) == 0) {
                    to_visit.push(current + inst.length);
                }

                if ((inst.is_jump() || inst.is_call())) {
                    auto target = inst.get_branch_target();
                    if (target && visited.count(target) == 0) {
                        to_visit.push(target);
                    }
                }

                if (inst.is_return()) {
                    continue;
                }
            }

            return flow;
        }

        std::vector<uintptr_t> find_code_caves(size_t minimum_size, ProcessInfo* proc_info) {
            std::vector<uintptr_t> caves;

            auto regions = proc_info->enumerate_regions();

            for (const auto& region : regions) {
                if (!region.is_executable()) {
                    continue;
                }

                std::vector<uint8_t> buffer(region.size);
                if (!proc_info->read_memory(region.base, buffer.data(), region.size)) {
                    continue;
                }

                size_t cave_start = 0;
                size_t cave_size = 0;
                bool in_cave = false;

                for (size_t i = 0; i < region.size; ++i) {
                    uint8_t byte = buffer[i];

                    if (byte == 0x00 || byte == 0x90 || byte == 0xCC) {
                        if (!in_cave) {
                            cave_start = i;
                            in_cave = true;
                        }
                        cave_size++;
                    }
                    else {
                        if (in_cave && cave_size >= minimum_size) {
                            caves.push_back(region.base + cave_start);
                        }
                        in_cave = false;
                        cave_size = 0;
                    }
                }

                if (in_cave && cave_size >= minimum_size) {
                    caves.push_back(region.base + cave_start);
                }
            }

            return caves;
        }

        std::vector<std::pair<uintptr_t, std::string>> find_string_references(ProcessInfo* proc_info) {
            std::vector<std::pair<uintptr_t, std::string>> references;

            auto regions = proc_info->enumerate_regions();
            PatternScanner scanner(proc_info);

            std::vector<std::pair<uintptr_t, std::string>> strings;

            for (const auto& region : regions) {
                if (!region.is_readable() || region.is_executable()) {
                    continue;
                }

                std::vector<uint8_t> buffer(region.size);
                if (!proc_info->read_memory(region.base, buffer.data(), region.size)) {
                    continue;
                }

                for (size_t i = 0; i < region.size - 4; ++i) {
                    if (buffer[i] >= 0x20 && buffer[i] < 0x7F) {
                        std::string str;
                        size_t j = i;

                        while (j < region.size && buffer[j] >= 0x20 && buffer[j] < 0x7F) {
                            str += static_cast<char>(buffer[j]);
                            j++;
                        }

                        if (str.length() >= 4 && buffer[j] == 0) {
                            strings.push_back({ region.base + i, str });
                            i = j;
                        }
                    }
                }
            }

            for (const auto& [str_addr, str] : strings) {
                auto refs = scanner.scan_xrefs(str_addr);

                for (uintptr_t ref : refs) {
                    references.push_back({ ref, str });
                }
            }

            return references;
        }

    }

}
