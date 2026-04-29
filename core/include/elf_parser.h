#ifndef ELF_PARSER_H
#define ELF_PARSER_H

// TODO: День 4 — реализовать полный ELF-парсер.
// Сейчас только объявление класса, чтобы main.cpp мог включать этот заголовок.

#include <string>

class ELFParser {
public:
    explicit ELFParser(const std::string& filepath) : filepath_(filepath) {}
    bool parse() { return false; }  // заглушка
    std::string getError() const { return "ELF parser not implemented yet"; }

private:
    std::string filepath_;
};

#endif // ELF_PARSER_H
