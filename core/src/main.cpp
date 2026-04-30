#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <iomanip>
#include <sstream>

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

std::vector<uint8_t> readFile(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file) return {};
    const std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(static_cast<size_t>(size));
    if (size > 0 && !file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        return {};
    }
    return buffer;
}

/**
 * Экранирование строки для JSON.
 * Заменяет проблемные символы: " \ \n \r \t и контрольные.
 */
std::string jsonEscape(const std::string& s) {
    std::ostringstream oss;
    for (const char c : s) {
        switch (c) {
            case '"':  oss << "\\\""; break;
            case '\\': oss << "\\\\"; break;
            case '\b': oss << "\\b"; break;
            case '\f': oss << "\\f"; break;
            case '\n': oss << "\\n"; break;
            case '\r': oss << "\\r"; break;
            case '\t': oss << "\\t"; break;
            default:
                if (static_cast<uint8_t>(c) < 0x20) {
                    oss << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<int>(static_cast<uint8_t>(c));
                    oss << std::dec;
                } else {
                    oss << c;
                }
        }
    }
    return oss.str();
}

std::string toHexAddr(uint64_t value) {
    std::ostringstream oss;
    oss << "0x" << std::hex << value;
    return oss.str();
}

void printElfJson(const std::string& filepath, const ElfInfo& elf,
                  const std::vector<uint8_t>& data,
                  const std::string& md5, const std::string& sha256,
                  double entropy)
{
    std::cout << "{";
    std::cout << R"("schema_version":"1.0",)";
    std::cout << R"("format":"ELF",)";
    std::cout << R"("filepath":")" << jsonEscape(filepath) << R"(",)";
    std::cout << R"("size":)" << data.size() << ",";
    std::cout << R"("md5":")" << md5 << R"(",)";
    std::cout << R"("sha256":")" << sha256 << R"(",)";
    std::cout << R"("entropy":)" << std::fixed << std::setprecision(4) << entropy << ",";

    if (!elf.valid) {
        std::cout << R"("parse_error":")" << jsonEscape(elf.error) << R"(")";
        std::cout << "}" << std::endl;
        return;
    }

    std::cout << R"("elf_class":)" << elf.elfClass << ",";
    std::cout << R"("endianness":")" << elf.endianness << R"(",)";
    std::cout << R"("type":")" << elf.type << R"(",)";
    std::cout << R"("arch":")" << elf.architecture << R"(",)";
    std::cout << R"("entry_point":")" << toHexAddr(elf.entryPoint) << R"(",)";

    // Sections
    std::cout << R"("sections":[)";
    for (size_t i = 0; i < elf.sections.size(); ++i) {
        const ElfSection& s = elf.sections[i];
        if (i > 0) std::cout << ",";
        std::cout << "{"
                  << R"("name":")"    << jsonEscape(s.name) << R"(",)"
                  << R"("address":")" << toHexAddr(s.address) << R"(",)"
                  << R"("offset":)"   << s.offset << ","
                  << R"("size":)"     << s.size << ","
                  << R"("flags":")"   << s.flags << R"(",)"
                  << R"("entropy":)"  << std::fixed << std::setprecision(4) << s.entropy
                  << "}";
    }
    std::cout << "],";

    // Imports
    std::cout << R"("imports":[)";
    for (size_t i = 0; i < elf.imports.size(); ++i) {
        if (i > 0) std::cout << ",";
        std::cout << "\"" << jsonEscape(elf.imports[i]) << "\"";
    }
    std::cout << "],";

    // Strings (ограничим первыми 1000, чтобы JSON не разрастался слишком сильно)
    const size_t strLimit = std::min(elf.strings.size(), static_cast<size_t>(1000));
    std::cout << R"("strings":[)";
    for (size_t i = 0; i < strLimit; ++i) {
        if (i > 0) std::cout << ",";
        std::cout << "\"" << jsonEscape(elf.strings[i]) << "\"";
    }
    std::cout << "],";
    std::cout << R"("string_count":)" << elf.strings.size();

    std::cout << "}" << std::endl;
}

void printElfHuman(const std::string& filepath, const ElfInfo& elf,
                   const std::vector<uint8_t>& data,
                   const std::string& md5, const std::string& sha256,
                   double entropy)
{
    std::cout << "=== Binary Recon ===" << std::endl;
    std::cout << "File:        " << filepath << std::endl;
    std::cout << "Format:      ELF" << std::endl;
    std::cout << "Size:        " << data.size() << " bytes" << std::endl;
    std::cout << "MD5:         " << md5 << std::endl;
    std::cout << "SHA256:      " << sha256 << std::endl;
    std::cout << "Entropy:     " << std::fixed << std::setprecision(4) << entropy << std::endl;

    if (!elf.valid) {
        std::cout << std::endl;
        std::cout << "Parse error: " << elf.error << std::endl;
        return;
    }

    std::cout << "Class:       ELF" << elf.elfClass << std::endl;
    std::cout << "Endianness:  " << elf.endianness << std::endl;
    std::cout << "Type:        " << elf.type << std::endl;
    std::cout << "Arch:        " << elf.architecture << std::endl;
    std::cout << "Entry:       " << toHexAddr(elf.entryPoint) << std::endl;
    std::cout << std::endl;

    std::cout << "Sections (" << elf.sections.size() << "):" << std::endl;
    for (const ElfSection& s : elf.sections) {
        if (s.name.empty()) continue;
        std::cout << "  " << std::left << std::setw(20) << s.name
                  << " " << std::setw(10) << toHexAddr(s.address)
                  << " size=" << std::setw(8) << std::right << s.size
                  << " flags=" << std::setw(4) << std::left << s.flags
                  << " H=" << std::fixed << std::setprecision(2) << s.entropy
                  << std::endl;
    }
    std::cout << std::endl;

    std::cout << "Imports (" << elf.imports.size() << "):" << std::endl;
    for (size_t i = 0; i < std::min(elf.imports.size(), static_cast<size_t>(15)); ++i) {
        std::cout << "  " << elf.imports[i] << std::endl;
    }
    if (elf.imports.size() > 15) {
        std::cout << "  ... and " << (elf.imports.size() - 15) << " more" << std::endl;
    }
    std::cout << std::endl;

    std::cout << "Strings extracted: " << elf.strings.size() << std::endl;
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

    const FileFormat format = FormatDetector::detect(filepath);
    if (format == FileFormat::UNKNOWN) {
        if (jsonMode) {
            std::cout << R"({"error":"Unknown or unreadable file format"})" << std::endl;
        } else {
            std::cerr << "Error: Unknown or unreadable file format: " << filepath << std::endl;
        }
        return 1;
    }

    const std::vector<uint8_t> data = readFile(filepath);
    if (data.empty()) {
        if (jsonMode) {
            std::cout << R"({"error":"Cannot read file or file is empty"})" << std::endl;
        } else {
            std::cerr << "Error: Cannot read file: " << filepath << std::endl;
        }
        return 1;
    }

    const std::string md5    = Hashes::md5(data.data(), data.size());
    const std::string sha256 = Hashes::sha256(data.data(), data.size());
    const double entropy     = Entropy::calculate(data);

    if (format == FileFormat::ELF) {
        ELFParser parser(data.data(), data.size());
        const ElfInfo info = parser.parse();
        if (jsonMode) {
            printElfJson(filepath, info, data, md5, sha256, entropy);
        } else {
            printElfHuman(filepath, info, data, md5, sha256, entropy);
        }
    } else {
        // PE — на Дне 5
        if (jsonMode) {
            std::cout << "{"
                      << R"("schema_version":"1.0",)"
                      << R"("format":"PE",)"
                      << R"("size":)" << data.size() << ","
                      << R"("md5":")" << md5 << R"(",)"
                      << R"("sha256":")" << sha256 << R"(",)"
                      << R"("entropy":)" << std::fixed << std::setprecision(4) << entropy << ","
                      << R"("status":"PE parser will be added in Day 5")"
                      << "}" << std::endl;
        } else {
            std::cout << "=== Binary Recon ===" << std::endl;
            std::cout << "File:    " << filepath << std::endl;
            std::cout << "Format:  PE" << std::endl;
            std::cout << "Size:    " << data.size() << " bytes" << std::endl;
            std::cout << "MD5:     " << md5 << std::endl;
            std::cout << "SHA256:  " << sha256 << std::endl;
            std::cout << "Entropy: " << std::fixed << std::setprecision(4) << entropy << std::endl;
            std::cout << "PE parser will be added in Day 5." << std::endl;
        }
    }

    return 0;
}
