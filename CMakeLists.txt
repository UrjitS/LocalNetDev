cmake_minimum_required(VERSION 4.0)
project(LocalNet)
set(CMAKE_CXX_STANDARD 20)

# Point CMake at the custom prefix
list(APPEND CMAKE_PREFIX_PATH "$ENV{HOME}/.local")

# Find Binc library
find_library(BINC_LIB NAMES Binc PATHS "$ENV{HOME}/.local/lib")
find_path(BINC_INCLUDE_DIR NAMES adapter.h PATH_SUFFIXES binc PATHS "$ENV{HOME}/.local/include")

# Find GLib using pkg-config
include(FindPkgConfig)
pkg_check_modules(GLIB REQUIRED glib-2.0 gio-2.0)

# Print found paths for debugging
message(STATUS "BINC_LIB: ${BINC_LIB}")
message(STATUS "BINC_INCLUDE_DIR: ${BINC_INCLUDE_DIR}")
message(STATUS "GLIB_LIBRARIES: ${GLIB_LIBRARIES}")
message(STATUS "GLIB_INCLUDE_DIRS: ${GLIB_INCLUDE_DIRS}")

include_directories(${CMAKE_SOURCE_DIR}/bluetooth)
include_directories(${CMAKE_SOURCE_DIR}/protocol)
include_directories(${CMAKE_SOURCE_DIR}/encryption)
include_directories(${CMAKE_SOURCE_DIR}/routing)
include_directories(${CMAKE_SOURCE_DIR}/utils)
include_directories(${CMAKE_SOURCE_DIR}/tests)

add_executable(LocalNet
        main.c
        bluetooth/bluetooth.c
        protocol/protocol.c
        encryption/encryption.c
        routing/routing.c
        utils/utils.c
        utils/utils.h
)

# Add include directories
target_include_directories(LocalNet PRIVATE
        ${BINC_INCLUDE_DIR}
        ${GLIB_INCLUDE_DIRS}
)

# Link libraries - order matters: Binc, then GLib, then system libs
target_link_libraries(LocalNet PRIVATE
        ${BINC_LIB}
        ${GLIB_LIBRARIES}
        m
)

# Add GLib link directories
target_link_directories(LocalNet PRIVATE ${GLIB_LIBRARY_DIRS})

# Test binary for protocol unit tests
add_executable(protocol_tests
        protocol/protocol.c
        tests/test_protocol.c
)

target_include_directories(protocol_tests PRIVATE ${CMAKE_SOURCE_DIR}/protocol)

# Test binary for routing unit tests
add_executable(routing_tests
        routing/routing.c
        tests/test_routing.c
)

target_include_directories(routing_tests PRIVATE ${CMAKE_SOURCE_DIR}/routing)
