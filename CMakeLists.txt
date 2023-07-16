cmake_minimum_required(VERSION 3.10)

project(rotom)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(GNUInstallDirs)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/3rd/linenoise
    ${CMAKE_CURRENT_SOURCE_DIR}/3rd/libelfin
)

file(GLOB SRCS
    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/3rd/linenoise/linenoise.c
)

add_executable(${CMAKE_PROJECT_NAME} ${SRCS})

add_custom_target(
    libelfin
    COMMAND make
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/3rd/libelfin
)

target_link_libraries(${CMAKE_PROJECT_NAME}
    ${CMAKE_CURRENT_SOURCE_DIR}/3rd/libelfin/dwarf/libdwarf++.so
    ${CMAKE_CURRENT_SOURCE_DIR}/3rd/libelfin/elf/libelf++.so
)

add_dependencies(${CMAKE_PROJECT_NAME} libelfin)
