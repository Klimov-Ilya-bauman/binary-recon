#include "pe_parser.h"
#include "entropy.h"
#include <cstring>
#include <algorithm>
#include <set>

namespace {

// =============================================================================
//                  СТРУКТУРЫ PE/COFF (упрощённые)
// =============================================================================
//
// Полные определения — в Microsoft PE/COFF specification.
// Все поля little-endian.
// =============================================================================

#pragma pack(push, 1)

// MS-DOS header — первые 64 байта PE-файла.
// Большинство полей унаследованы от DOS и нам не нужны.
struct DosHeader {
    uint16_t e_magic;       // должно быть 'M' 'Z' (0x5A4D)
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;      // ← смещение PE Signature 'PE\0\0'
};

// COFF header — общий для PE и для .obj файлов.
struct CoffHeader {
    uint16_t Machine;            // тип процессора
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

// Optional Header для PE32 (32-bit).
struct OptionalHeader32 {
    uint16_t Magic;              // 0x10B = PE32, 0x20B = PE32+
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;          // в PE32 — 32 бита
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
};

// Optional Header для PE32+ (64-bit).
// Отличия от PE32: ImageBase 64-битный + некоторые stack/heap поля 64-битные,
// нет BaseOfData.
struct OptionalHeader64 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;          // ← 64 бита в PE32+
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve; // 64
    uint64_t SizeOfStackCommit;  // 64
    uint64_t SizeOfHeapReserve;  // 64
    uint64_t SizeOfHeapCommit;   // 64
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
};

// Запись в таблице Data Directories.
struct DataDirectory {
    uint32_t VirtualAddress;     // RVA таблицы
    uint32_t Size;
};

// Заголовок секции (40 байт).
struct SectionHeader {
    char     Name[8];            // имя, не обязательно null-terminated
    uint32_t VirtualSize;
    uint32_t VirtualAddress;     // RVA в памяти
    uint32_t SizeOfRawData;      // размер на диске
    uint32_t PointerToRawData;   // смещение в файле
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

// Запись Import Directory Table.
struct ImportDescriptor {
    uint32_t OriginalFirstThunk; // RVA на массив имён функций (Import Lookup Table)
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;               // RVA на имя DLL (ASCII)
    uint32_t FirstThunk;         // RVA на Import Address Table (резервируется loader'ом)
};

#pragma pack(pop)

// =============================================================================
//                              КОНСТАНТЫ
// =============================================================================

// Machine values
constexpr uint16_t IMAGE_FILE_MACHINE_I386    = 0x014c;
constexpr uint16_t IMAGE_FILE_MACHINE_AMD64   = 0x8664;
constexpr uint16_t IMAGE_FILE_MACHINE_ARM     = 0x01c0;
constexpr uint16_t IMAGE_FILE_MACHINE_ARM64   = 0xaa64;

// Optional Header magic
constexpr uint16_t IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b;
constexpr uint16_t IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;

// Section flags (Characteristics)
constexpr uint32_t IMAGE_SCN_CNT_CODE          = 0x00000020;
constexpr uint32_t IMAGE_SCN_CNT_INITIALIZED   = 0x00000040;
constexpr uint32_t IMAGE_SCN_CNT_UNINITIALIZED = 0x00000080;
constexpr uint32_t IMAGE_SCN_MEM_EXECUTE       = 0x20000000;
constexpr uint32_t IMAGE_SCN_MEM_READ          = 0x40000000;
constexpr uint32_t IMAGE_SCN_MEM_WRITE         = 0x80000000;

// Subsystems
constexpr uint16_t IMAGE_SUBSYSTEM_NATIVE      = 1;
constexpr uint16_t IMAGE_SUBSYSTEM_WINDOWS_GUI = 2;
constexpr uint16_t IMAGE_SUBSYSTEM_WINDOWS_CUI = 3;

// Indexes в Data Directories
constexpr int DIR_IMPORT = 1;

// =============================================================================
//                          ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// =============================================================================

std::string machineToString(uint16_t machine) {
    switch (machine) {
        case IMAGE_FILE_MACHINE_I386:  return "x86";
        case IMAGE_FILE_MACHINE_AMD64: return "x86_64";
        case IMAGE_FILE_MACHINE_ARM:   return "ARM";
        case IMAGE_FILE_MACHINE_ARM64: return "ARM64";
        default:                       return "unknown";
    }
}

std::string subsystemToString(uint16_t subsystem) {
    switch (subsystem) {
        case IMAGE_SUBSYSTEM_NATIVE:      return "native";
        case IMAGE_SUBSYSTEM_WINDOWS_GUI: return "gui";
        case IMAGE_SUBSYSTEM_WINDOWS_CUI: return "console";
        default:                          return "other";
    }
}

std::string characteristicsToString(uint32_t ch) {
    std::string result;
    if (ch & IMAGE_SCN_MEM_READ)    result += "R";
    if (ch & IMAGE_SCN_MEM_WRITE)   result += "W";
    if (ch & IMAGE_SCN_MEM_EXECUTE) result += "X";
    return result;
}

/**
 * Преобразует RVA (Relative Virtual Address) в смещение внутри файла.
 *
 * При загрузке PE Windows-loader разворачивает секции по их VirtualAddress,
 * но в файле они лежат по PointerToRawData. Нам, читая файл, нужно
 * пересчитать обратно.
 *
 * Алгоритм: ищем секцию [VA, VA + SizeOfRawData), в которую попадает RVA,
 * и считаем file_offset = (rva - VA) + PointerToRawData.
 *
 * @return file offset, или (size_t)-1 если RVA не попадает ни в одну секцию.
 */
size_t rvaToOffset(uint32_t rva, const std::vector<SectionHeader>& sections) {
    for (const SectionHeader& s : sections) {
        const uint32_t start = s.VirtualAddress;
        const uint32_t end   = s.VirtualAddress + std::max(s.VirtualSize, s.SizeOfRawData);
        if (rva >= start && rva < end) {
            return s.PointerToRawData + (rva - start);
        }
    }
    return static_cast<size_t>(-1);
}

/**
 * Безопасное чтение null-terminated ASCII строки из файла.
 */
std::string readAsciiString(const uint8_t* data, size_t length, size_t offset, size_t maxLen = 256) {
    if (offset >= length) return {};
    const size_t available = length - offset;
    const size_t limit = std::min(available, maxLen);
    const uint8_t* p = data + offset;
    size_t end = 0;
    while (end < limit && p[end] != 0) {
        ++end;
    }
    return std::string(reinterpret_cast<const char*>(p), end);
}

/**
 * Извлечение ASCII-строк длиной >= 4 (как в ELF-парсере).
 */
std::vector<std::string> extractStrings(const uint8_t* data, size_t length, size_t minLen = 4) {
    std::vector<std::string> result;
    std::string current;
    for (size_t i = 0; i < length; ++i) {
        const uint8_t c = data[i];
        if ((c >= 0x20 && c <= 0x7E) || c == '\t') {
            current += static_cast<char>(c);
        } else {
            if (current.length() >= minLen) result.push_back(current);
            current.clear();
        }
    }
    if (current.length() >= minLen) result.push_back(current);
    return result;
}

} // anonymous namespace

// =============================================================================
//                          РЕАЛИЗАЦИЯ PEParser
// =============================================================================

PeInfo PEParser::parse() {
    PeInfo info{};
    info.valid = false;

    // 1. DOS Header.
    if (length_ < sizeof(DosHeader)) {
        info.error = "File too small for DOS header";
        return info;
    }
    DosHeader dos;
    std::memcpy(&dos, data_, sizeof(dos));
    if (dos.e_magic != 0x5A4D) {
        info.error = "Invalid DOS magic (expected MZ)";
        return info;
    }

    // 2. PE Signature по e_lfanew.
    if (dos.e_lfanew + 4 > length_) {
        info.error = "PE signature offset out of bounds";
        return info;
    }
    const uint8_t* peSig = data_ + dos.e_lfanew;
    if (peSig[0] != 'P' || peSig[1] != 'E' || peSig[2] != 0 || peSig[3] != 0) {
        info.error = "Invalid PE signature";
        return info;
    }

    // 3. COFF Header — сразу после PE Signature.
    const size_t coffOffset = dos.e_lfanew + 4;
    if (coffOffset + sizeof(CoffHeader) > length_) {
        info.error = "Truncated COFF header";
        return info;
    }
    CoffHeader coff;
    std::memcpy(&coff, data_ + coffOffset, sizeof(coff));

    info.architecture = machineToString(coff.Machine);

    // 4. Optional Header — определяем класс PE по Magic.
    const size_t optOffset = coffOffset + sizeof(CoffHeader);
    if (optOffset + 2 > length_) {
        info.error = "Truncated Optional Header";
        return info;
    }
    uint16_t optMagic;
    std::memcpy(&optMagic, data_ + optOffset, 2);

    uint64_t imageBase    = 0;
    uint32_t entryRVA     = 0;
    uint16_t subsystem    = 0;
    uint32_t numRvaSizes  = 0;
    size_t   dataDirOffset = 0;

    if (optMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        info.peClass = 32;
        if (optOffset + sizeof(OptionalHeader32) > length_) {
            info.error = "Truncated PE32 Optional Header";
            return info;
        }
        OptionalHeader32 opt;
        std::memcpy(&opt, data_ + optOffset, sizeof(opt));
        imageBase     = opt.ImageBase;
        entryRVA      = opt.AddressOfEntryPoint;
        subsystem     = opt.Subsystem;
        numRvaSizes   = opt.NumberOfRvaAndSizes;
        dataDirOffset = optOffset + sizeof(OptionalHeader32);
    } else if (optMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        info.peClass = 64;
        if (optOffset + sizeof(OptionalHeader64) > length_) {
            info.error = "Truncated PE32+ Optional Header";
            return info;
        }
        OptionalHeader64 opt;
        std::memcpy(&opt, data_ + optOffset, sizeof(opt));
        imageBase     = opt.ImageBase;
        entryRVA      = opt.AddressOfEntryPoint;
        subsystem     = opt.Subsystem;
        numRvaSizes   = opt.NumberOfRvaAndSizes;
        dataDirOffset = optOffset + sizeof(OptionalHeader64);
    } else {
        info.error = "Unknown Optional Header magic";
        return info;
    }

    info.imageBase  = imageBase;
    info.entryPoint = entryRVA;
    info.subsystem  = subsystemToString(subsystem);

    // 5. Data Directories — массив (RVA, size) по 8 байт каждый.
    if (dataDirOffset + numRvaSizes * sizeof(DataDirectory) > length_) {
        info.error = "Data Directories out of bounds";
        return info;
    }
    std::vector<DataDirectory> dataDirs(numRvaSizes);
    std::memcpy(dataDirs.data(), data_ + dataDirOffset,
                numRvaSizes * sizeof(DataDirectory));

    // 6. Section Headers — после Optional Header (учитывая SizeOfOptionalHeader).
    const size_t sectionOffset = optOffset + coff.SizeOfOptionalHeader;
    if (sectionOffset + coff.NumberOfSections * sizeof(SectionHeader) > length_) {
        info.error = "Section headers out of bounds";
        return info;
    }

    std::vector<SectionHeader> rawSections(coff.NumberOfSections);
    for (uint16_t i = 0; i < coff.NumberOfSections; ++i) {
        std::memcpy(&rawSections[i],
                    data_ + sectionOffset + i * sizeof(SectionHeader),
                    sizeof(SectionHeader));
    }

    // Заполняем info.sections.
    for (const SectionHeader& s : rawSections) {
        PeSection sec{};
        // Name — 8 байт ASCII, может быть без терминатора.
        char nameBuf[9] = {0};
        std::memcpy(nameBuf, s.Name, 8);
        sec.name        = std::string(nameBuf);
        sec.virtualAddr = s.VirtualAddress;
        sec.virtualSize = s.VirtualSize;
        sec.rawSize     = s.SizeOfRawData;
        sec.rawOffset   = s.PointerToRawData;
        sec.flags       = characteristicsToString(s.Characteristics);

        if (s.SizeOfRawData > 0
            && s.PointerToRawData + s.SizeOfRawData <= length_)
        {
            sec.entropy = Entropy::calculate(data_ + s.PointerToRawData, s.SizeOfRawData);
        } else {
            sec.entropy = 0.0;
        }
        info.sections.push_back(sec);
    }

    // 7. Import Directory.
    if (numRvaSizes > DIR_IMPORT && dataDirs[DIR_IMPORT].VirtualAddress != 0) {
        const uint32_t impRVA  = dataDirs[DIR_IMPORT].VirtualAddress;
        const size_t   impOff  = rvaToOffset(impRVA, rawSections);
        if (impOff != static_cast<size_t>(-1)) {
            // Массив ImportDescriptor'ов до нулевого терминатора.
            size_t cursor = impOff;
            std::set<std::string> seenFunctions;  // дедупликация

            while (cursor + sizeof(ImportDescriptor) <= length_) {
                ImportDescriptor desc;
                std::memcpy(&desc, data_ + cursor, sizeof(desc));
                cursor += sizeof(ImportDescriptor);

                // Нулевой descriptor — конец таблицы.
                if (desc.Name == 0 && desc.FirstThunk == 0) break;

                // Имя DLL.
                const size_t dllNameOff = rvaToOffset(desc.Name, rawSections);
                if (dllNameOff == static_cast<size_t>(-1)) continue;
                const std::string dllName = readAsciiString(data_, length_, dllNameOff);

                // Import Lookup Table (или FirstThunk если OriginalFirstThunk == 0).
                const uint32_t iltRVA = (desc.OriginalFirstThunk != 0)
                                        ? desc.OriginalFirstThunk
                                        : desc.FirstThunk;
                const size_t iltOff = rvaToOffset(iltRVA, rawSections);
                if (iltOff == static_cast<size_t>(-1)) continue;

                // Размер записи в ILT — 4 байта в PE32, 8 в PE32+.
                const size_t entrySize = (info.peClass == 64) ? 8 : 4;
                // Старший бит указывает на ordinal-импорт (без имени).
                const uint64_t ordinalFlag = (info.peClass == 64) ? 0x8000000000000000ULL
                                                                  : 0x80000000ULL;

                size_t entry = iltOff;
                while (entry + entrySize <= length_) {
                    uint64_t value = 0;
                    std::memcpy(&value, data_ + entry, entrySize);
                    if (value == 0) break;
                    entry += entrySize;

                    if (value & ordinalFlag) continue;  // импорт по ordinal — пропускаем

                    // value — RVA на структуру: hint(2 байта) + name(ASCII).
                    const size_t hintNameOff = rvaToOffset(static_cast<uint32_t>(value), rawSections);
                    if (hintNameOff == static_cast<size_t>(-1)) continue;
                    if (hintNameOff + 2 >= length_) continue;

                    const std::string fnName = readAsciiString(data_, length_, hintNameOff + 2);
                    if (fnName.empty()) continue;

                    const std::string key = dllName + "|" + fnName;
                    if (seenFunctions.count(key) == 0) {
                        seenFunctions.insert(key);
                        info.imports.push_back({dllName, fnName});
                    }
                }
            }
        }
    }

    // 8. Извлечение строк из всего файла.
    info.strings = extractStrings(data_, length_);

    info.valid = true;
    return info;
}
