#include "elf_parser.h"
#include "entropy.h"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace {

// =============================================================================
//                  СТРУКТУРЫ ELF (упрощённые, по спецификации)
// =============================================================================
//
// Полные определения — в /usr/include/elf.h.
// Мы повторяем их вручную, чтобы не зависеть от системного elf.h
// и чтобы код компилировался кросс-платформенно.
//
// Все ELF-файлы little-endian (по крайней мере на x86, ARM, RISC-V).
// Поэтому простой memcpy в наши структуры будет работать.
// =============================================================================

#pragma pack(push, 1)  // запрещаем компилятору выравнивать поля

// ELF64 header (40 байт + e_ident).
struct Elf64_Ehdr {
    uint8_t  e_ident[16];   // магия + класс + endianness + версия + ABI
    uint16_t e_type;        // тип файла (EXEC/DYN/REL/...)
    uint16_t e_machine;     // архитектура процессора
    uint32_t e_version;
    uint64_t e_entry;       // entry point virtual address
    uint64_t e_phoff;       // program header offset
    uint64_t e_shoff;       // section header offset
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;   // размер одного section header'а
    uint16_t e_shnum;       // количество section header'ов
    uint16_t e_shstrndx;    // индекс секции с именами секций (.shstrtab)
};

// ELF64 section header.
struct Elf64_Shdr {
    uint32_t sh_name;       // offset в .shstrtab
    uint32_t sh_type;       // SHT_PROGBITS / SHT_SYMTAB / ...
    uint64_t sh_flags;      // SHF_WRITE / SHF_ALLOC / SHF_EXECINSTR
    uint64_t sh_addr;       // адрес в виртуальной памяти
    uint64_t sh_offset;     // смещение в файле
    uint64_t sh_size;       // размер секции
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
};

// ELF64 symbol entry.
struct Elf64_Sym {
    uint32_t st_name;       // offset в .dynstr / .strtab
    uint8_t  st_info;       // тип (FUNC/OBJECT/...) и binding (LOCAL/GLOBAL/WEAK)
    uint8_t  st_other;
    uint16_t st_shndx;      // индекс секции, в которой определён символ
    uint64_t st_value;
    uint64_t st_size;
};

// Аналоги для 32-битного ELF.
struct Elf32_Ehdr {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct Elf32_Shdr {
    uint32_t sh_name;
    uint32_t sh_type;
    uint32_t sh_flags;
    uint32_t sh_addr;
    uint32_t sh_offset;
    uint32_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint32_t sh_addralign;
    uint32_t sh_entsize;
};

struct Elf32_Sym {
    uint32_t st_name;
    uint32_t st_value;
    uint32_t st_size;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
};

#pragma pack(pop)

// =============================================================================
//                              КОНСТАНТЫ
// =============================================================================

// e_type
constexpr uint16_t ET_REL  = 1;  // relocatable (.o файл)
constexpr uint16_t ET_EXEC = 2;  // executable
constexpr uint16_t ET_DYN  = 3;  // shared object (.so) или PIE-исполняемый

// e_machine
constexpr uint16_t EM_386     = 3;
constexpr uint16_t EM_ARM     = 40;
constexpr uint16_t EM_X86_64  = 62;
constexpr uint16_t EM_AARCH64 = 183;
constexpr uint16_t EM_RISCV   = 243;

// sh_type
constexpr uint32_t SHT_PROGBITS = 1;   // обычные данные/код
constexpr uint32_t SHT_SYMTAB   = 2;   // таблица символов
constexpr uint32_t SHT_STRTAB   = 3;   // таблица строк
constexpr uint32_t SHT_DYNSYM   = 11;  // таблица динамических символов

// sh_flags
constexpr uint64_t SHF_WRITE     = 0x1;
constexpr uint64_t SHF_ALLOC     = 0x2;
constexpr uint64_t SHF_EXECINSTR = 0x4;

// st_info: нижние 4 бита = тип
constexpr uint8_t STT_FUNC = 2;

// st_shndx: специальное значение для импортируемых символов.
constexpr uint16_t SHN_UNDEF = 0;

// =============================================================================
//                          ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// =============================================================================

std::string typeToString(uint16_t e_type) {
    switch (e_type) {
        case ET_REL:  return "REL";
        case ET_EXEC: return "EXEC";
        case ET_DYN:  return "DYN";
        default:      return "OTHER";
    }
}

std::string machineToString(uint16_t e_machine) {
    switch (e_machine) {
        case EM_386:     return "x86";
        case EM_X86_64:  return "x86_64";
        case EM_ARM:     return "ARM";
        case EM_AARCH64: return "ARM64";
        case EM_RISCV:   return "RISC-V";
        default:         return "unknown";
    }
}

std::string flagsToString(uint64_t flags) {
    std::string result;
    if (flags & SHF_WRITE)     result += "W";
    if (flags & SHF_ALLOC)     result += "A";
    if (flags & SHF_EXECINSTR) result += "X";
    return result;
}

/**
 * Безопасное чтение C-строки из таблицы строк.
 * Возвращает пустую строку, если offset выходит за границы.
 */
std::string readStringFromTable(const uint8_t* tableStart, size_t tableSize, uint32_t offset) {
    if (offset >= tableSize) {
        return {};
    }
    // Ищем нулевой байт от offset, но не дальше границы.
    const uint8_t* p   = tableStart + offset;
    const uint8_t* end = tableStart + tableSize;
    const uint8_t* q   = p;
    while (q < end && *q != 0) {
        ++q;
    }
    return std::string(reinterpret_cast<const char*>(p), q - p);
}

/**
 * Извлекает все печатаемые ASCII-строки длиной >= minLen из произвольных данных.
 * Аналог утилиты `strings`.
 */
std::vector<std::string> extractStrings(const uint8_t* data, size_t length, size_t minLen = 4) {
    std::vector<std::string> result;
    std::string current;

    for (size_t i = 0; i < length; ++i) {
        const uint8_t c = data[i];
        // Печатаемые ASCII (включая пробел, табуляцию)
        if ((c >= 0x20 && c <= 0x7E) || c == '\t') {
            current += static_cast<char>(c);
        } else {
            if (current.length() >= minLen) {
                result.push_back(current);
            }
            current.clear();
        }
    }
    // Хвостовая строка, если файл оканчивается без терминатора.
    if (current.length() >= minLen) {
        result.push_back(current);
    }
    return result;
}

} // anonymous namespace

// =============================================================================
//                          РЕАЛИЗАЦИЯ ELFParser
// =============================================================================

ElfInfo ELFParser::parse() {
    ElfInfo info{};
    info.valid = false;

    // 1. Базовая проверка размера.
    if (length_ < 16) {
        info.error = "File too small to be ELF";
        return info;
    }

    // 2. Магические байты уже проверены FormatDetector'ом, но повторим
    // на случай прямого вызова парсера.
    if (data_[0] != 0x7F || data_[1] != 'E' || data_[2] != 'L' || data_[3] != 'F') {
        info.error = "Not an ELF file";
        return info;
    }

    // 3. Класс (32 или 64 бит) — байт e_ident[4].
    //    1 = ELFCLASS32, 2 = ELFCLASS64.
    const uint8_t elfClassByte = data_[4];
    if (elfClassByte != 1 && elfClassByte != 2) {
        info.error = "Invalid ELF class";
        return info;
    }
    info.elfClass = (elfClassByte == 2) ? 64 : 32;

    // 4. Endianness — байт e_ident[5]. 1 = LE, 2 = BE.
    const uint8_t elfDataByte = data_[5];
    if (elfDataByte == 1) {
        info.endianness = "little";
    } else if (elfDataByte == 2) {
        info.endianness = "big";
        info.error = "Big-endian ELF is not supported";
        return info;
    } else {
        info.error = "Invalid ELF data encoding";
        return info;
    }

    // 5. Парсинг заголовка — разный для 32 и 64 бит.
    uint64_t entry         = 0;
    uint16_t e_type        = 0;
    uint16_t e_machine     = 0;
    uint64_t shoff         = 0;
    uint16_t shentsize     = 0;
    uint16_t shnum         = 0;
    uint16_t shstrndx      = 0;

    if (info.elfClass == 64) {
        if (length_ < sizeof(Elf64_Ehdr)) {
            info.error = "Truncated ELF64 header";
            return info;
        }
        Elf64_Ehdr ehdr;
        std::memcpy(&ehdr, data_, sizeof(ehdr));
        entry      = ehdr.e_entry;
        e_type     = ehdr.e_type;
        e_machine  = ehdr.e_machine;
        shoff      = ehdr.e_shoff;
        shentsize  = ehdr.e_shentsize;
        shnum      = ehdr.e_shnum;
        shstrndx   = ehdr.e_shstrndx;
    } else {
        if (length_ < sizeof(Elf32_Ehdr)) {
            info.error = "Truncated ELF32 header";
            return info;
        }
        Elf32_Ehdr ehdr;
        std::memcpy(&ehdr, data_, sizeof(ehdr));
        entry      = ehdr.e_entry;
        e_type     = ehdr.e_type;
        e_machine  = ehdr.e_machine;
        shoff      = ehdr.e_shoff;
        shentsize  = ehdr.e_shentsize;
        shnum      = ehdr.e_shnum;
        shstrndx   = ehdr.e_shstrndx;
    }

    info.entryPoint   = entry;
    info.type         = typeToString(e_type);
    info.architecture = machineToString(e_machine);

    // 6. Section headers — массив shnum элементов по shentsize байт.
    if (shoff == 0 || shnum == 0) {
        // ELF без секций — допустим (например, stripped objects),
        // но в нашем случае нечего извлекать.
        info.valid = true;
        return info;
    }
    if (shoff + static_cast<uint64_t>(shnum) * shentsize > length_) {
        info.error = "Section headers out of file bounds";
        return info;
    }

    // 7. Сначала прочитаем .shstrtab — таблицу имён секций.
    if (shstrndx >= shnum) {
        info.error = "Invalid shstrndx";
        return info;
    }

    auto readShdr64 = [&](uint16_t idx) {
        Elf64_Shdr s;
        std::memcpy(&s, data_ + shoff + idx * shentsize, sizeof(s));
        return s;
    };
    auto readShdr32 = [&](uint16_t idx) {
        Elf32_Shdr s;
        std::memcpy(&s, data_ + shoff + idx * shentsize, sizeof(s));
        return s;
    };

    // Указатель и размер .shstrtab.
    uint64_t shstrtabOff  = 0;
    uint64_t shstrtabSize = 0;
    if (info.elfClass == 64) {
        const Elf64_Shdr s = readShdr64(shstrndx);
        shstrtabOff  = s.sh_offset;
        shstrtabSize = s.sh_size;
    } else {
        const Elf32_Shdr s = readShdr32(shstrndx);
        shstrtabOff  = s.sh_offset;
        shstrtabSize = s.sh_size;
    }
    if (shstrtabOff + shstrtabSize > length_) {
        info.error = "shstrtab out of bounds";
        return info;
    }
    const uint8_t* shstrtab = data_ + shstrtabOff;

    // 8. Запоминаем .dynsym и .dynstr для извлечения импортов.
    uint64_t dynsymOff   = 0, dynsymSize   = 0, dynsymEntsize = 0;
    uint64_t dynstrOff   = 0, dynstrSize   = 0;

    // 9. Проходим все секции, заполняем info.sections + ищем .dynsym/.dynstr.
    for (uint16_t i = 0; i < shnum; ++i) {
        ElfSection sec{};
        uint32_t sh_type = 0;
        uint64_t sh_flags = 0;
        uint64_t sh_offset = 0, sh_size = 0, sh_addr = 0;
        uint32_t sh_name = 0;
        uint64_t sh_entsize = 0;

        if (info.elfClass == 64) {
            const Elf64_Shdr s = readShdr64(i);
            sh_name = s.sh_name; sh_type = s.sh_type; sh_flags = s.sh_flags;
            sh_addr = s.sh_addr; sh_offset = s.sh_offset; sh_size = s.sh_size;
            sh_entsize = s.sh_entsize;
        } else {
            const Elf32_Shdr s = readShdr32(i);
            sh_name = s.sh_name; sh_type = s.sh_type; sh_flags = s.sh_flags;
            sh_addr = s.sh_addr; sh_offset = s.sh_offset; sh_size = s.sh_size;
            sh_entsize = s.sh_entsize;
        }

        sec.name    = readStringFromTable(shstrtab, shstrtabSize, sh_name);
        sec.address = sh_addr;
        sec.offset  = sh_offset;
        sec.size    = sh_size;
        sec.flags   = flagsToString(sh_flags);

        // Энтропия секции — только если есть содержимое.
        if (sh_size > 0 && sh_offset + sh_size <= length_ && sh_type != 8 /*SHT_NOBITS*/) {
            sec.entropy = Entropy::calculate(data_ + sh_offset, static_cast<size_t>(sh_size));
        } else {
            sec.entropy = 0.0;
        }

        info.sections.push_back(sec);

        // Запомнить .dynsym и .dynstr.
        if (sh_type == SHT_DYNSYM) {
            dynsymOff = sh_offset; dynsymSize = sh_size; dynsymEntsize = sh_entsize;
        }
        if (sh_type == SHT_STRTAB && sec.name == ".dynstr") {
            dynstrOff = sh_offset; dynstrSize = sh_size;
        }
    }

    // 10. Извлечение импортов из .dynsym.
    if (dynsymOff > 0 && dynsymSize > 0 && dynstrOff > 0 && dynstrSize > 0
        && dynsymOff + dynsymSize <= length_
        && dynstrOff + dynstrSize <= length_)
    {
        const uint8_t* dynstr = data_ + dynstrOff;

        if (info.elfClass == 64 && dynsymEntsize >= sizeof(Elf64_Sym)) {
            const size_t count = static_cast<size_t>(dynsymSize / dynsymEntsize);
            for (size_t i = 0; i < count; ++i) {
                Elf64_Sym sym;
                std::memcpy(&sym, data_ + dynsymOff + i * dynsymEntsize, sizeof(sym));
                // Нас интересуют импорты: undefined символы (st_shndx == 0).
                if (sym.st_shndx == SHN_UNDEF && sym.st_name != 0) {
                    const std::string name =
                        readStringFromTable(dynstr, dynstrSize, sym.st_name);
                    if (!name.empty()) {
                        info.imports.push_back(name);
                    }
                }
            }
        } else if (info.elfClass == 32 && dynsymEntsize >= sizeof(Elf32_Sym)) {
            const size_t count = static_cast<size_t>(dynsymSize / dynsymEntsize);
            for (size_t i = 0; i < count; ++i) {
                Elf32_Sym sym;
                std::memcpy(&sym, data_ + dynsymOff + i * dynsymEntsize, sizeof(sym));
                if (sym.st_shndx == SHN_UNDEF && sym.st_name != 0) {
                    const std::string name =
                        readStringFromTable(dynstr, dynstrSize, sym.st_name);
                    if (!name.empty()) {
                        info.imports.push_back(name);
                    }
                }
            }
        }
    }

    // 11. Удаляем дубликаты импортов и сортируем.
    std::sort(info.imports.begin(), info.imports.end());
    info.imports.erase(std::unique(info.imports.begin(), info.imports.end()),
                       info.imports.end());

    // 12. Извлечение строк из всего файла.
    info.strings = extractStrings(data_, length_);

    info.valid = true;
    return info;
}
