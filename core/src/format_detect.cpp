#include "format_detect.h"
#include <fstream>
#include <vector>

FileFormat FormatDetector::detect(const std::string& filepath) {
    // Открываем файл в бинарном режиме. std::ios::binary важен:
    // без него на Windows ifstream преобразовывал бы \r\n -> \n,
    // что ломает работу с бинарными данными.
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        return FileFormat::UNKNOWN;  // файл не существует или нет прав
    }

    // Читаем первые 4 байта — максимум, нужный для определения.
    // ELF требует 4 байта, PE — только 2, но читаем сразу 4 для универсальности.
    std::vector<uint8_t> magic(4);
    file.read(reinterpret_cast<char*>(magic.data()), 4);

    // file.gcount() — сколько байт реально прочитано.
    // Если файл короче 4 байт — это точно не ELF и не PE.
    if (file.gcount() < 4) {
        return FileFormat::UNKNOWN;
    }

    // ELF: 0x7F 'E' 'L' 'F'
    if (magic[0] == 0x7F && magic[1] == 'E' &&
        magic[2] == 'L' && magic[3] == 'F') {
        return FileFormat::ELF;
    }

    // PE: 'M' 'Z' (первые два байта). Настоящая PE сигнатура "PE\0\0"
    // находится по смещению из поля e_lfanew в DOS-заголовке, но для
    // определения формата достаточно MZ — это корректно для всех PE/DOS.
    if (magic[0] == 'M' && magic[1] == 'Z') {
        return FileFormat::PE;
    }

    return FileFormat::UNKNOWN;
}

std::string FormatDetector::formatToString(FileFormat format) {
    switch (format) {
        case FileFormat::ELF:     return "ELF";
        case FileFormat::PE:      return "PE";
        case FileFormat::UNKNOWN: return "UNKNOWN";
    }
    // Защита от компилятора: если кто-то добавит новый enum value и забудет
    // его здесь, -Wswitch предупредит. Этот return unreachable при правильном enum.
    return "UNKNOWN";
}
