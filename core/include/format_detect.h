#ifndef FORMAT_DETECT_H
#define FORMAT_DETECT_H

#include <string>
#include <cstdint>

/**
 * Перечисление поддерживаемых форматов исполняемых файлов.
 * UNKNOWN возвращается, если файл не опознан или не читается.
 */
enum class FileFormat {
    UNKNOWN,
    ELF,   // Executable and Linkable Format (Linux, *BSD)
    PE     // Portable Executable (Windows .exe, .dll)
};

/**
 * Статический класс для определения формата файла по magic bytes.
 * Не создаёт экземпляров — только статические методы.
 */
class FormatDetector {
public:
    /**
     * Определяет формат файла, читая его первые байты.
     * @param filepath Абсолютный или относительный путь к файлу.
     * @return Один из FileFormat. UNKNOWN если файл нельзя открыть
     *         или магические байты не распознаны.
     */
    static FileFormat detect(const std::string& filepath);

    /**
     * Преобразует enum в читаемое имя формата.
     */
    static std::string formatToString(FileFormat format);

private:
    // Магические байты форматов — известные константы из спецификаций.
    // ELF: 0x7F 'E' 'L' 'F' (ELF spec, section 1.4)
    // PE:  'M' 'Z'          (остаток от MS-DOS; PE signature дальше в файле)
    static constexpr uint8_t ELF_MAGIC[] = {0x7F, 'E', 'L', 'F'};
    static constexpr uint8_t PE_MAGIC[]  = {'M', 'Z'};
};

#endif // FORMAT_DETECT_H
