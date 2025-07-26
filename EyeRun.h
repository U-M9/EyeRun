#pragma once

#include <Windows.h>
#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <optional>
#include <functional>
#include <unordered_map>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <queue>      
#include <set>        

namespace EyeRun {

    class Instruction;
    class Disassembler;
    class PatternScanner;
    class ProcessInfo;

    enum class Register : uint8_t {

        RAX = 0, RCX = 1, RDX = 2, RBX = 3,
        RSP = 4, RBP = 5, RSI = 6, RDI = 7,
        R8 = 8, R9 = 9, R10 = 10, R11 = 11,
        R12 = 12, R13 = 13, R14 = 14, R15 = 15,

        EAX = 16, ECX = 17, EDX = 18, EBX = 19,
        ESP = 20, EBP = 21, ESI = 22, EDI = 23,
        R8D = 24, R9D = 25, R10D = 26, R11D = 27,
        R12D = 28, R13D = 29, R14D = 30, R15D = 31,

        AX = 32, CX = 33, DX = 34, BX = 35,
        SP = 36, BP = 37, SI = 38, DI = 39,
        R8W = 40, R9W = 41, R10W = 42, R11W = 43,
        R12W = 44, R13W = 45, R14W = 46, R15W = 47,

        AL = 48, CL = 49, DL = 50, BL = 51,
        AH = 52, CH = 53, DH = 54, BH = 55,
        SPL = 56, BPL = 57, SIL = 58, DIL = 59,
        R8B = 60, R9B = 61, R10B = 62, R11B = 63,
        R12B = 64, R13B = 65, R14B = 66, R15B = 67,

        RIP = 68,

        CS = 70, SS = 71, DS = 72, ES = 73, FS = 74, GS = 75,

        CR0 = 80, CR2 = 81, CR3 = 82, CR4 = 83, CR8 = 84,

        DR0 = 90, DR1 = 91, DR2 = 92, DR3 = 93,
        DR4 = 94, DR5 = 95, DR6 = 96, DR7 = 97,

        MM0 = 100, MM1 = 101, MM2 = 102, MM3 = 103,
        MM4 = 104, MM5 = 105, MM6 = 106, MM7 = 107,

        XMM0 = 110, XMM1 = 111, XMM2 = 112, XMM3 = 113,
        XMM4 = 114, XMM5 = 115, XMM6 = 116, XMM7 = 117,
        XMM8 = 118, XMM9 = 119, XMM10 = 120, XMM11 = 121,
        XMM12 = 122, XMM13 = 123, XMM14 = 124, XMM15 = 125,

        YMM0 = 130, YMM1 = 131, YMM2 = 132, YMM3 = 133,
        YMM4 = 134, YMM5 = 135, YMM6 = 136, YMM7 = 137,
        YMM8 = 138, YMM9 = 139, YMM10 = 140, YMM11 = 141,
        YMM12 = 142, YMM13 = 143, YMM14 = 144, YMM15 = 145,

        NONE = 255
    };

    struct Prefixes {

        bool lock = false;
        bool repne = false;
        bool repe = false;
        bool cs_override = false;
        bool ss_override = false;
        bool ds_override = false;
        bool es_override = false;
        bool fs_override = false;
        bool gs_override = false;
        bool operand_size = false;
        bool address_size = false;

        uint8_t rex = 0;

        bool has_vex = false;
        uint8_t vex_bytes[3] = { 0 };

        bool has_rex() const { return rex != 0; }
        bool rex_w() const { return (rex & 0x08) != 0; }
        bool rex_r() const { return (rex & 0x04) != 0; }
        bool rex_x() const { return (rex & 0x02) != 0; }
        bool rex_b() const { return (rex & 0x01) != 0; }
    };

    enum class OperandType : uint8_t {
        None,
        Register,
        Memory,
        Immediate,
        Relative,
        Absolute,
        Segment,
        Control,
        Debug,
        MMX,
        XMM,
        YMM,
        ZMM
    };

    enum class MemorySize : uint8_t {
        Default = 0,
        Byte = 1,
        Word = 2,
        Dword = 4,
        Qword = 8,
        Tword = 10,
        Oword = 16,
        Yword = 32,
        Zword = 64
    };

    struct Operand {
        OperandType type = OperandType::None;

        Register reg = Register::NONE;

        Register base = Register::NONE;
        Register index = Register::NONE;
        uint8_t scale = 0;
        int64_t displacement = 0;
        Register segment = Register::NONE;

        union {
            uint64_t immediate;
            int64_t imm_signed;
        };

        uint8_t size = 0;
        MemorySize mem_size = MemorySize::Default;

        bool is_rip_relative = false;
        bool is_implicit = false;

        std::string to_string(bool intel_syntax = true) const;

        bool is_memory() const { return type == OperandType::Memory; }
        bool is_register() const { return type == OperandType::Register; }
        bool is_immediate() const { return type == OperandType::Immediate; }
    };

    enum class InstructionFlags : uint32_t {
        None = 0,
        ModifiesStack = 1 << 0,
        ControlFlow = 1 << 1,
        Conditional = 1 << 2,
        Privileged = 1 << 3,
        SSE = 1 << 4,
        AVX = 1 << 5,
        FPU = 1 << 6,
        RepeatPrefix = 1 << 7,
        LockPrefix = 1 << 8,
        String = 1 << 9,
        RipRelative = 1 << 10,
        HasModRM = 1 << 11,
        HasSIB = 1 << 12,
        HasImmediate = 1 << 13,
        HasDisplacement = 1 << 14
    };

    inline InstructionFlags operator|(InstructionFlags a, InstructionFlags b) {
        return static_cast<InstructionFlags>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
    }

    inline InstructionFlags operator&(InstructionFlags a, InstructionFlags b) {
        return static_cast<InstructionFlags>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
    }

    inline InstructionFlags& operator|=(InstructionFlags& a, InstructionFlags b) {
        a = a | b;
        return a;
    }

    class Instruction {
    public:

        uintptr_t address = 0;
        std::vector<uint8_t> bytes;
        size_t length = 0;

        std::string mnemonic;
        std::vector<Operand> operands;
        Prefixes prefixes;
        uint32_t flags = 0;

        bool is_rip_relative = false;
        uintptr_t rip_target = 0;

        bool is_jump() const;
        bool is_call() const;
        bool is_return() const;
        bool is_conditional() const;
        uintptr_t get_branch_target() const;

        std::string to_string(bool show_bytes = true, bool intel_syntax = true) const;

        Operand& source() { return operands.size() > 0 ? operands[0] : dummy_operand; }
        Operand& destination() { return operands.size() > 1 ? operands[1] : dummy_operand; }
        const Operand& source() const { return operands.size() > 0 ? operands[0] : dummy_operand; }
        const Operand& destination() const { return operands.size() > 1 ? operands[1] : dummy_operand; }

        bool has_flag(InstructionFlags flag) const { return (flags & static_cast<uint32_t>(flag)) != 0; }
        void set_flag(InstructionFlags flag) { flags |= static_cast<uint32_t>(flag); }

    private:
        static Operand dummy_operand;
    };

    struct MemoryRegion {
        uintptr_t base = 0;
        size_t size = 0;
        DWORD protection = 0;
        DWORD state = 0;
        DWORD type = 0;
        std::string module_name;

        bool is_readable() const;
        bool is_writable() const;
        bool is_executable() const;
        bool is_guard_page() const;
        bool contains(uintptr_t address) const;
        std::string protection_string() const;
    };

    struct SectionInfo {
        std::string name;
        uintptr_t virtual_address = 0;
        size_t virtual_size = 0;
        uintptr_t raw_address = 0;
        size_t raw_size = 0;
        uint32_t characteristics = 0;

        bool is_executable() const;
        bool is_readable() const;
        bool is_writable() const;
    };

    struct ModuleInfo {
        std::string name;
        std::string path;
        uintptr_t base = 0;
        size_t size = 0;
        HMODULE handle = nullptr;
        std::vector<SectionInfo> sections;

        std::optional<SectionInfo> find_section(const std::string& name) const;
        std::optional<SectionInfo> find_section_by_address(uintptr_t address) const;
    };

    class ProcessInfo {
    public:

        ProcessInfo(HANDLE process = GetCurrentProcess());
        ProcessInfo(const ProcessInfo&) = delete;
        ProcessInfo& operator=(const ProcessInfo&) = delete;
        ~ProcessInfo();

        bool attach(const std::string& process_name);
        bool attach(DWORD pid);
        void detach();

        bool read_memory(uintptr_t address, void* buffer, size_t size) const;
        bool write_memory(uintptr_t address, const void* buffer, size_t size);

        template<typename T>
        std::optional<T> read(uintptr_t address) const {
            T value;
            if (read_memory(address, &value, sizeof(T))) {
                return value;
            }
            return std::nullopt;
        }

        template<typename T>
        bool write(uintptr_t address, const T& value) {
            return write_memory(address, &value, sizeof(T));
        }

        std::vector<MemoryRegion> enumerate_regions() const;
        std::optional<MemoryRegion> find_region(uintptr_t address) const;
        std::vector<MemoryRegion> find_regions_by_protection(DWORD protection_mask) const {
            std::vector<MemoryRegion> result;
            auto all_regions = enumerate_regions();
            for (const auto& region : all_regions) {
                if (region.protection & protection_mask) {
                    result.push_back(region);
                }
            }
            return result;
        }

        std::vector<ModuleInfo> enumerate_modules() const;
        std::optional<ModuleInfo> find_module(const std::string& module_name) const;
        uintptr_t get_module_base(const std::string& module_name) const;
        uintptr_t get_proc_address(const std::string& module_name, const std::string& proc_name) const;

        std::optional<IMAGE_DOS_HEADER> read_dos_header(uintptr_t base) const;
        std::optional<IMAGE_NT_HEADERS64> read_nt_headers(uintptr_t base) const;
        std::vector<SectionInfo> read_sections(uintptr_t base) const;

        HANDLE get_handle() const { return process_handle; }
        DWORD get_pid() const { return process_id; }
        bool is_external() const { return external_mode; }
        bool is_x64() const;

        uintptr_t allocate(size_t size, DWORD protection = PAGE_EXECUTE_READWRITE);
        bool free(uintptr_t address);

    private:
        HANDLE process_handle = nullptr;
        DWORD process_id = 0;
        bool external_mode = false;
        bool owns_handle = false;

        mutable std::vector<ModuleInfo> module_cache;
        mutable bool modules_cached = false;
        void refresh_module_cache() const;
    };

    struct DisassemblerConfig {
        bool intel_syntax = true;
        bool show_symbols = true;
        bool decode_vex = true;
        size_t max_instruction_length = 15;
    };

    class Disassembler {
    public:
        explicit Disassembler(ProcessInfo* proc_info, const DisassemblerConfig& config = {});

        Instruction disassemble(uintptr_t address);

        std::vector<Instruction> disassemble_range(uintptr_t start, uintptr_t end);
        std::vector<Instruction> disassemble_count(uintptr_t start, size_t count);
        std::vector<Instruction> disassemble_until(uintptr_t start,
            std::function<bool(const Instruction&)> predicate);

        void set_config(const DisassemblerConfig& config) { this->config = config; }
        const DisassemblerConfig& get_config() const { return config; }

        void add_symbol(uintptr_t address, const std::string& name);
        std::optional<std::string> resolve_symbol(uintptr_t address) const;

    private:
        ProcessInfo* process_info;
        DisassemblerConfig config;
        std::unordered_map<uintptr_t, std::string> symbols;

        struct DecodingContext;

        bool decode_instruction(DecodingContext& ctx, Instruction& inst);
        bool decode_prefixes(DecodingContext& ctx);
        bool decode_opcode(DecodingContext& ctx);
        bool decode_modrm(DecodingContext& ctx);
        bool decode_sib(DecodingContext& ctx);
        bool decode_displacement(DecodingContext& ctx);
        bool decode_immediate(DecodingContext& ctx);

        void decode_operands(DecodingContext& ctx, Instruction& inst);
        Operand decode_modrm_operand(DecodingContext& ctx, bool is_reg_field);
        Register decode_register_operand(uint8_t reg, uint8_t size, bool rex_ext);

        void handle_rip_relative(DecodingContext& ctx, Instruction& inst);
        std::string get_register_name(Register reg) const;
    };

    struct PatternConfig {
        bool scan_executable_only = true;
        bool case_sensitive = true;
        size_t alignment = 1;
        size_t max_results = 0;
    };

    class PatternScanner {
    public:
        explicit PatternScanner(ProcessInfo* proc_info, const PatternConfig& config = {});

        std::vector<uintptr_t> scan(const std::string& pattern,
            uintptr_t start = 0,
            uintptr_t end = 0);

        std::vector<uintptr_t> scan_module(const std::string& pattern,
            const std::string& module_name);

        std::vector<uintptr_t> scan_all_modules(const std::string& pattern);

        std::vector<uintptr_t> scan_string(const std::string& str,
            bool unicode = false,
            uintptr_t start = 0,
            uintptr_t end = 0);

        std::vector<uintptr_t> scan_xrefs(uintptr_t target,
            uintptr_t start = 0,
            uintptr_t end = 0);

        std::vector<uintptr_t> scan_calls(uintptr_t target,
            uintptr_t start = 0,
            uintptr_t end = 0);

        static std::string generate_pattern(const uint8_t* bytes, size_t length,
            const bool* wildcards = nullptr);

        void set_config(const PatternConfig& config) { this->config = config; }
        const PatternConfig& get_config() const { return config; }

    private:
        ProcessInfo* process_info;
        PatternConfig config;

        struct Pattern {
            std::vector<uint8_t> bytes;
            std::vector<bool> mask;
        };

        Pattern parse_pattern(const std::string& pattern);
        bool match_pattern(const uint8_t* data, const Pattern& pattern);

        std::vector<uintptr_t> scan_region(const MemoryRegion& region, const Pattern& pattern);

        bool is_call_instruction(const uint8_t* bytes, uintptr_t& target, uintptr_t address);
        bool is_jump_instruction(const uint8_t* bytes, uintptr_t& target, uintptr_t address);
    };

    enum class HookType {
        JMP,
        CALL,
        PUSH_RET,
        NOP_SLIDE,
        TRAMPOLINE
    };

    namespace Hooks {

        bool place_hook(uintptr_t from, uintptr_t to, HookType type, ProcessInfo* proc_info);
        bool place_jmp(uintptr_t from, uintptr_t to, ProcessInfo* proc_info);
        bool place_call(uintptr_t from, uintptr_t to, ProcessInfo* proc_info);
        bool place_push_ret(uintptr_t from, uintptr_t to, ProcessInfo* proc_info);

        bool place_nop(uintptr_t address, size_t count, ProcessInfo* proc_info);
        bool place_nop_sled(uintptr_t address, size_t count, ProcessInfo* proc_info);

        struct TrampolineInfo {
            uintptr_t original_address = 0;
            uintptr_t hook_address = 0;
            uintptr_t trampoline_address = 0;
            size_t hook_size = 0;
            std::vector<uint8_t> original_bytes;
        };

        std::optional<TrampolineInfo> create_trampoline(uintptr_t from, uintptr_t to,
            ProcessInfo* proc_info);
        bool remove_trampoline(const TrampolineInfo& info, ProcessInfo* proc_info);

        class Detour {
        public:
            Detour(uintptr_t target, uintptr_t hook, ProcessInfo* proc_info);
            ~Detour();

            bool install();
            bool uninstall();
            bool is_installed() const { return installed; }

            uintptr_t get_original() const { return trampoline_address; }

        private:
            ProcessInfo* proc_info;
            uintptr_t target_address = 0;
            uintptr_t hook_address = 0;
            uintptr_t trampoline_address = 0;
            std::vector<uint8_t> original_bytes;
            size_t hook_size = 0;
            bool installed = false;
        };
    }

    namespace Memory {

        DWORD set_protection(uintptr_t address, size_t size, DWORD new_protect, ProcessInfo* proc_info);

        std::vector<uint8_t> pattern_to_bytes(const std::string& pattern);
        std::string bytes_to_pattern(const uint8_t* bytes, size_t length);

        size_t get_instruction_length(uintptr_t address, ProcessInfo* proc_info);
        size_t calculate_hook_size(uintptr_t address, size_t minimum_size, ProcessInfo* proc_info);

        uintptr_t resolve_rip_relative(uintptr_t instruction_address, int32_t offset, size_t instruction_length);
        int32_t calculate_relative_offset(uintptr_t from, uintptr_t to, size_t instruction_length);

        std::string read_string(uintptr_t address, ProcessInfo* proc_info, size_t max_length = 256);
        std::wstring read_wstring(uintptr_t address, ProcessInfo* proc_info, size_t max_length = 256);
    }

    namespace Analysis {

        struct FunctionInfo {
            uintptr_t start = 0;
            uintptr_t end = 0;
            std::vector<uintptr_t> calls;
            std::vector<uintptr_t> jumps;
            std::vector<uintptr_t> xrefs;
            bool has_prologue = false;
            bool has_epilogue = false;
        };

        std::optional<FunctionInfo> analyze_function(uintptr_t address, ProcessInfo* proc_info);
        std::vector<uintptr_t> find_function_calls(uintptr_t function_start, ProcessInfo* proc_info);
        std::vector<uintptr_t> find_function_xrefs(uintptr_t function_address, ProcessInfo* proc_info);

        std::vector<uintptr_t> trace_execution_flow(uintptr_t start, ProcessInfo* proc_info);
        std::vector<uintptr_t> find_code_caves(size_t minimum_size, ProcessInfo* proc_info);

        bool is_function_prologue(uintptr_t address, ProcessInfo* proc_info);
        bool is_function_epilogue(uintptr_t address, ProcessInfo* proc_info);

        std::vector<std::pair<uintptr_t, std::string>> find_string_references(ProcessInfo* proc_info);
    }

}