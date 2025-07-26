#include "EyeRun.h"
#include <Psapi.h>
#include <TlHelp32.h>
#include <cstring>

namespace EyeRun {

    bool ProcessInfo::attach(const std::string& process_name) {
        // Find process by name and open a handle
        DWORD pid = 0;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return false;

        PROCESSENTRY32 entry = { sizeof(entry) };
        if (Process32First(snapshot, &entry)) {
            do {
                if (_stricmp(entry.szExeFile, process_name.c_str()) == 0) {
                    pid = entry.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot, &entry));
        }
        CloseHandle(snapshot);

        if (pid == 0)
            return false;

        return attach(pid);
    }

    bool ProcessInfo::attach(DWORD pid) {
        HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProc)
            return false;

        if (process_handle && owns_handle)
            CloseHandle(process_handle);

        process_handle = hProc;
        process_id = pid;
        external_mode = true;
        owns_handle = true;
        modules_cached = false;
        return true;
    }

    void ProcessInfo::detach() {
        if (process_handle && owns_handle) {
            CloseHandle(process_handle);
            process_handle = nullptr;
            process_id = 0;
            external_mode = false;
            owns_handle = false;
            modules_cached = false;
        }
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
            if (!operands.empty() && (operands[0].type == OperandType::Relative ||
                operands[0].type == OperandType::Absolute)) {
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

    bool ProcessInfo::read_memory(uintptr_t address, void* buffer, size_t size) const {
        if (!external_mode) {

            __try {
                memcpy(buffer, reinterpret_cast<const void*>(address), size);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                return false;
            }
        }

        SIZE_T bytes_read;
        return ReadProcessMemory(process_handle, reinterpret_cast<LPCVOID>(address),
            buffer, size, &bytes_read) && bytes_read == size;
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

                regions.push_back(region);
            }

            address = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        }

        return regions;
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

        uint8_t read_u8() {
            if (offset >= max_size) return 0;
            return data[offset++];
        }

        uint32_t read_u32() {
            if (offset + 3 >= max_size) return 0;
            uint32_t value = *reinterpret_cast<const uint32_t*>(&data[offset]);
            offset += 4;
            return value;
        }

        uint8_t modrm_mod() const { return (modrm >> 6) & 0x03; }
        uint8_t modrm_reg() const { return (modrm >> 3) & 0x07; }
        uint8_t modrm_rm() const { return modrm & 0x07; }
    };

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

    bool MemoryRegion::is_executable() const {
        return (protection & PAGE_EXECUTE) ||
            (protection & PAGE_EXECUTE_READ) ||
            (protection & PAGE_EXECUTE_READWRITE) ||
            (protection & PAGE_EXECUTE_WRITECOPY);
    }

    bool MemoryRegion::is_readable() const {
        return (protection & PAGE_READONLY) ||
            (protection & PAGE_READWRITE) ||
            (protection & PAGE_EXECUTE_READ) ||
            (protection & PAGE_EXECUTE_READWRITE);
    }

    std::string MemoryRegion::protection_string() const {
        std::string result;

        if (protection & PAGE_EXECUTE) result += "X";
        else result += "-";

        if (is_readable()) result += "R";
        else result += "-";

        if (protection & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) {
            result += "W";
        }
        else {
            result += "-";
        }

        return result;
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

    std::vector<uintptr_t> PatternScanner::scan_region(const MemoryRegion& region, const Pattern& pattern) {
        std::vector<uintptr_t> results;

        if (pattern.bytes.empty()) {
            return results;
        }

        std::vector<uint8_t> buffer(region.size);

        if (!process_info->read_memory(region.base, buffer.data(), region.size)) {
            return results;
        }

        size_t scan_end = region.size - pattern.bytes.size() + 1;

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

    namespace Memory {

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

    }

    namespace Analysis {

        std::vector<uintptr_t> trace_execution_flow(uintptr_t start, ProcessInfo* proc_info) {
            std::vector<uintptr_t> flow;
            std::set<uintptr_t> visited;
            std::queue<uintptr_t> to_visit;

            to_visit.push(start);
            Disassembler disasm(proc_info);

            while (!to_visit.empty()) {
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

                if (!inst.is_jump() || inst.is_conditional()) {
                    to_visit.push(current + inst.length);
                }

                if (inst.is_jump() || inst.is_call()) {
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

    }

}