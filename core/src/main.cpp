#include <iostream>
#include <string>
#include <cstring>

#include "format_detect.h"
#include "elf_parser.h"
#include "pe_parser.h"

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

} // anonymous namespace

int main(int argc, char* argv[]) {
    // Проверка аргументов
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    if (std::strcmp(argv[1], "-h") == 0 ||
        std::strcmp(argv[1], "--help") == 0) {
        printUsage(argv[0]);
        return 0;
    }

    std::string filepath = argv[1];
    bool jsonMode = (argc > 2 && std::strcmp(argv[2], "--json") == 0);

    // Определение формата
    FileFormat format = FormatDetector::detect(filepath);

    if (format == FileFormat::UNKNOWN) {
        if (jsonMode) {
            std::cout << R"({"error":"Unknown or unreadable file format"})"
                      << std::endl;
        } else {
            std::cerr << "Error: Unknown or unreadable file format: "
                      << filepath << std::endl;
        }
        return 1;
    }

    // День 2: на этом этапе просто рапортуем о формате.
    // Полный парсинг появится в Днях 4-5.
    if (jsonMode) {
        std::cout << R"({"schema_version":"1.0","format":")"
                  << FormatDetector::formatToString(format)
                  << R"(","status":"stub","message":"Core skeleton, parsers not implemented yet"})"
                  << std::endl;
    } else {
        std::cout << "=== Binary Recon Core (skeleton) ===" << std::endl;
        std::cout << "File:   " << filepath << std::endl;
        std::cout << "Format: " << FormatDetector::formatToString(format) << std::endl;
        std::cout << "Status: Parser not implemented yet (see Day 4-5)" << std::endl;
    }

    return 0;
}
