#ifndef PE_PARSER_H
#define PE_PARSER_H

#include <string>
#include <vector>
#include <cstdint>

/**
 * Информация об одной секции PE-файла.
 */
struct PeSection {
    std::string name;        // имя секции (.text, .data, .rdata, ...)
    uint64_t    virtualAddr; // RVA — Relative Virtual Address
    uint64_t    virtualSize; // размер в памяти после загрузки
    uint64_t    rawSize;     // размер на диске (может отличаться от virtualSize)
    uint64_t    rawOffset;   // смещение в файле
    std::string flags;       // строковое представление характеристик: "RX", "RW", ...
    double      entropy;     // энтропия Шеннона по содержимому
};

/**
 * Импортируемая функция из конкретной DLL.
 */
struct PeImport {
    std::string dll;       // например "KERNEL32.dll"
    std::string function;  // например "IsDebuggerPresent"
};

/**
 * Полный результат парсинга PE-файла.
 */
struct PeInfo {
    bool                     valid;
    std::string              error;

    int                      peClass;       // 32 (PE32) или 64 (PE32+)
    std::string              architecture;  // x86, x86_64, ARM64, ...
    std::string              subsystem;     // console, gui, native
    uint64_t                 entryPoint;    // RVA точки входа
    uint64_t                 imageBase;     // базовый адрес загрузки

    std::vector<PeSection>   sections;
    std::vector<PeImport>    imports;
    std::vector<std::string> strings;
};

/**
 * Парсер PE-файлов (Portable Executable).
 *
 * Поддерживает PE32 (32-bit) и PE32+ (64-bit) для всех архитектур.
 * Big-endian PE не существует — формат всегда little-endian.
 *
 * Структура PE-файла (упрощённо):
 *   [DOS Header (64 байта)]
 *   [DOS Stub]
 *   [PE Signature 'PE\0\0']            ← по смещению e_lfanew
 *   [COFF Header (20 байт)]
 *   [Optional Header (224 или 240 байт)]
 *   [Section Headers]
 *   [Sections data]
 */
class PEParser {
public:
    PEParser(const uint8_t* data, size_t length)
        : data_(data), length_(length) {}

    PeInfo parse();

private:
    const uint8_t* data_;
    size_t         length_;
};

#endif // PE_PARSER_H
