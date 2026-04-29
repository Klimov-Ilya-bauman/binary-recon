#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <iomanip>

#include "format_detect.h"
#include "elf_parser.h"
#include "pe_parser.h"
#include "hashes.h"
#include "entropy.h"

namespace {

void printUsage(const char* prog) {
    std::cerr << "Binary Recon Core v1.0\n"
              << "Usage: " << prog << " <file> [--json]\n"
              << "\n"
              << "Options:\n"
              << "  --json    Output result as JSON (for pipeline use)\n"
              << "  -h        Show this help\n"
              << "\n"
              << "Supported formats: ELF (Linux), PE (Windows)\n";
}

/**
 * Читает файл целиком в память.
 * @return Содержимое файла. Пустой vector при ошибке.
 */
std::vector<uint8_t> readFile(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file) {
        return {};
    }
    const std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(static_cast<size_t>(size));
    if (size > 0 && !file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        return {};
    }
    return buffer;
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }
    if (std::strcmp(argv[1], "-h") == 0 || std::strcmp(argv[1], "--help") == 0) {
        printUsage(argv[0]);
        return 0;
    }

    const std::string filepath = argv[1];
    const bool jsonMode = (argc > 2 && std::strcmp(argv[2], "--json") == 0);

    // Определение формата.
    const FileFormat format = FormatDetector::detect(filepath);
    if (format == FileFormat::UNKNOWN) {
        if (jsonMode) {
            std::cout << R"({"error":"Unknown or unreadable file format"})" << std::endl;
        } else {
            std::cerr << "Error: Unknown or unreadable file format: " << filepath << std::endl;
        }
        return 1;
    }

    // Чтение содержимого файла.
    const std::vector<uint8_t> data = readFile(filepath);
    if (data.empty()) {
        if (jsonMode) {
            std::cout << R"({"error":"Cannot read file or file is empty"})" << std::endl;
        } else {
            std::cerr << "Error: Cannot read file or file is empty: " << filepath << std::endl;
        }
        return 1;
    }

    // Вычисление хешей и энтропии.
    const std::string md5Hash    = Hashes::md5(data.data(), data.size());
    const std::string sha256Hash = Hashes::sha256(data.data(), data.size());
    const double      entropyVal = Entropy::calculate(data);
    const std::string formatStr  = FormatDetector::formatToString(format);

    // Вывод.
    if (jsonMode) {
        std::cout << "{"
                  << R"("schema_version":"1.0",)"
                  << R"("format":")"  << formatStr  << R"(",)"
                  << R"("size":)"     << data.size() << ","
                  << R"("md5":")"     << md5Hash    << R"(",)"
                  << R"("sha256":")"  << sha256Hash << R"(",)"
                  << R"("entropy":)"  << std::fixed << std::setprecision(4) << entropyVal << ","
                  << R"("status":"partial","message":"Parsers will be added in Day 4-5")"
                  << "}" << std::endl;
    } else {
        std::cout << "=== Binary Recon ===" << std::endl;
        std::cout << "File:    " << filepath  << std::endl;
        std::cout << "Format:  " << formatStr << std::endl;
        std::cout << "Size:    " << data.size() << " bytes" << std::endl;
        std::cout << "MD5:     " << md5Hash    << std::endl;
        std::cout << "SHA256:  " << sha256Hash << std::endl;
        std::cout << "Entropy: " << std::fixed << std::setprecision(4) << entropyVal
                  << " (range 0.0 - 8.0)" << std::endl;
        std::cout << std::endl;
        std::cout << "Note: Section parsing not implemented yet (Day 4-5)" << std::endl;
    }

    return 0;
}
