cmake_minimum_required(VERSION 3.16)
project(binary_recon_core VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Предупреждения и оптимизация
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
    if(NOT CMAKE_BUILD_TYPE)
        set(CMAKE_BUILD_TYPE Release)
    endif()
endif()

# Основной исполняемый файл
add_executable(core
    src/main.cpp
    src/format_detect.cpp
    src/elf_parser.cpp
    src/pe_parser.cpp
    src/hashes.cpp
)

target_include_directories(core PRIVATE include)

# Установка
install(TARGETS core
    RUNTIME DESTINATION lib/binary-recon
)
