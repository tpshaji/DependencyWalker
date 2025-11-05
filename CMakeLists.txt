cmake_minimum_required(VERSION 3.20)
project(DependencyExplorer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build a Win32 GUI executable
add_executable(DependencyExplorer WIN32
    src/main.cpp
    src/pe_utils.cpp
    src/pe_utils.h
)

target_compile_definitions(DependencyExplorer PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

# Target Windows 10 API for modern functions
if(MSVC)
    target_compile_definitions(DependencyExplorer PRIVATE _WIN32_WINNT=0x0A00)
endif()

# Link required Windows libraries
target_link_libraries(DependencyExplorer PRIVATE
    comctl32
    ole32
    shell32
    user32
    gdi32
    advapi32
    oleaut32
)

# Set output directory
set_target_properties(DependencyExplorer PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
