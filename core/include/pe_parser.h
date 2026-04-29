#ifndef PE_PARSER_H
#define PE_PARSER_H

// TODO: День 5 — реализовать полный PE-парсер.

#include <string>

class PEParser {
public:
    PEParser() = default;
    bool loadFile(const std::string& /*filepath*/) { return false; }
    bool parse() { return false; }
    std::string getError() const { return "PE parser not implemented yet"; }
};

#endif // PE_PARSER_H
