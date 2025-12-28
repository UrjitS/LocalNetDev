cmake_minimum_required(VERSION 3.16)
project(LocalNet C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(BLUEZ REQUIRED bluez)

# Include directories
include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_SOURCE_DIR}/protocol)
include_directories(${CMAKE_SOURCE_DIR}/encryption)
include_directories(${CMAKE_SOURCE_DIR}/routing)
include_directories(${CMAKE_SOURCE_DIR}/utils)
include_directories(${CMAKE_SOURCE_DIR}/bluetooth)
include_directories(${CMAKE_SOURCE_DIR}/mesh)
include_directories(${CMAKE_SOURCE_DIR}/tests)
include_directories(${BLUEZ_INCLUDE_DIRS})

# Core library sources
set(LOCALNET_SOURCES
    protocol/protocol.c
    routing/routing.c
    bluetooth/bluetooth_transport.c
    mesh/mesh_network.c
    utils/utils.c
)

# Create static library
add_library(localnet_lib STATIC ${LOCALNET_SOURCES})
target_link_libraries(localnet_lib ${BLUEZ_LIBRARIES} pthread)
target_include_directories(localnet_lib PUBLIC ${CMAKE_SOURCE_DIR})

# Main executable
add_executable(LocalNet main.c)
target_link_libraries(LocalNet localnet_lib)

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

# Test binary for mesh routing tests (Milestone 3)
add_executable(mesh_routing_tests
    protocol/protocol.c
    routing/routing.c
    tests/test_mesh_routing.c
)
target_include_directories(mesh_routing_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/protocol
    ${CMAKE_SOURCE_DIR}/routing
)

# Enable testing
enable_testing()
add_test(NAME ProtocolTests COMMAND protocol_tests)
add_test(NAME RoutingTests COMMAND routing_tests)
add_test(NAME MeshRoutingTests COMMAND mesh_routing_tests)

# Compiler warnings
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(localnet_lib PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(LocalNet PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(protocol_tests PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(routing_tests PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(mesh_routing_tests PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Installation
install(TARGETS LocalNet RUNTIME DESTINATION bin)
install(TARGETS localnet_lib ARCHIVE DESTINATION lib)
install(FILES
    mesh/mesh_network.h
    protocol/protocol.h
    routing/routing.h
    bluetooth/bluetooth_transport.h
    DESTINATION include/localnet
)

# Print configuration summary
message(STATUS "")
message(STATUS "LocalNet Configuration Summary")
message(STATUS "------------------------------")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "BlueZ Libraries: ${BLUEZ_LIBRARIES}")
message(STATUS "")

