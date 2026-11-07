cmake_minimum_required(VERSION 3.16)
project(pe-binaries CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_executable(pe-binaries
    src/main.cpp
    src/pe.cpp
    src/checks.cpp
    src/hashing.cpp)

if(MSVC)
    target_compile_options(pe-binaries PRIVATE /W4)
else()
    target_compile_options(pe-binaries PRIVATE -Wall -Wextra)
endif()
