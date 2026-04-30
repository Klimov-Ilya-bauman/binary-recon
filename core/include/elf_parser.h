#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#include <string>
#include <vector>
#include <cstdint>

/**
 * Информация об одной секции ELF-файла.
 */
struct ElfSection {
    std::string name;        // имя секции (.text, .data, .rodata, ...)
    uint64_t    address;     // виртуальный адрес загрузки
    uint64_t    size;        // размер секции в байтах
    uint64_t    offset;      // смещение в файле
    std::string flags;       // строковое представление флагов: "AX", "WA", ...
    double      entropy;     // энтропия Шеннона по содержимому секции
};

/**
 * Полный результат парсинга ELF-файла.
 */
struct ElfInfo {
    bool                     valid;          // успешен ли парсинг
    std::string              error;          // описание ошибки, если valid == false

    // Метаданные из ELF Header.
    int                      elfClass;       // 32 или 64
    std::string              endianness;     // "little" или "big"
    std::string              type;           // EXEC, DYN, REL
    std::string              architecture;   // x86_64, x86, ARM64, ARM, ...
    uint64_t                 entryPoint;     // точка входа

    // Содержимое.
    std::vector<ElfSection>  sections;
    std::vector<std::string> imports;        // импортируемые функции
    std::vector<std::string> strings;        // ASCII-строки длины >= 4
};

/**
 * Парсер ELF-файлов (Executable and Linkable Format).
 *
 * Поддерживает ELF32 и ELF64, little-endian.
 * Big-endian (например, MIPS) не поддерживается — на современных
 * системах встречается крайне редко.
 *
 * Использование:
 *   ELFParser parser(data.data(), data.size());
 *   ElfInfo info = parser.parse();
 *   if (info.valid) { ... }
 */
class ELFParser {
public:
    /**
     * @param data    Указатель на начало содержимого ELF-файла в памяти.
     * @param length  Размер данных в байтах.
     */
    ELFParser(const uint8_t* data, size_t length)
        : data_(data), length_(length) {}

    /**
     * Выполняет полный парсинг.
     * @return Структура с результатом. Проверяй info.valid.
     */
    ElfInfo parse();

private:
    const uint8_t* data_;
    size_t         length_;
};

#endif // ELF_PARSER_H
