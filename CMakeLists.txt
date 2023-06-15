cmake_minimum_required(VERSION 3.10)

project(rotom)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(GNUInstallDirs)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/linenoise
)

file(GLOB SRCS
    ./src/*.cc
    ./linenoise/linenoise.c
)

add_executable(${CMAKE_PROJECT_NAME} ${SRCS})
