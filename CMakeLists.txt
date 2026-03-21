# ==============================================================================
# CMakeLists.txt — Industrial IoT Gateway Security Platform
# Target: Raspberry Pi 4, Linux, C++17
# ==============================================================================
cmake_minimum_required(VERSION 3.16)
project(iiot_gateway VERSION 1.0.0 LANGUAGES CXX)

# ------------------------------------------------------------------------------
# C++17 Standard — Required for std::optional, std::variant, structured bindings
# ------------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ------------------------------------------------------------------------------
# Build type defaults to Release for production deployment on Pi4
# Override with: cmake -DCMAKE_BUILD_TYPE=Debug ..
# ------------------------------------------------------------------------------
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG   "-g -O0 -Wall -Wextra -Wpedantic")

add_compile_options(-Wall -Wextra)

# ==============================================================================
# Source Files
# ==============================================================================
set(SOURCES
    src/main.cpp
    src/MqttClient.cpp
    src/DataProcessor.cpp
    src/DatabaseManager.cpp
    src/SnmpAgent.cpp
    src/Watchdog.cpp
)

# ==============================================================================
# Executable Target
# ==============================================================================
add_executable(${PROJECT_NAME} ${SOURCES})

# ------------------------------------------------------------------------------
# Include Directories
# ------------------------------------------------------------------------------
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include/models
)

# ==============================================================================
# Dependency Resolution
# ==============================================================================

# --- 1. Threads (pthreads) ---------------------------------------------------
find_package(Threads REQUIRED)

# --- 2. SQLite3 --------------------------------------------------------------
find_package(PkgConfig REQUIRED)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)

# --- 3. Mosquitto C++ wrapper (mosquittopp) ----------------------------------
# Install via: sudo apt install libmosquitto-dev libmosquittopp-dev
find_library(MOSQUITTO_LIB   mosquitto   REQUIRED)
find_library(MOSQUITTOPP_LIB mosquittopp REQUIRED)
find_path(MOSQUITTO_INCLUDE_DIR mosquittopp.h
    PATHS /usr/include /usr/local/include
    REQUIRED
)

# --- 4. Net-SNMP -------------------------------------------------------------
# Install via: sudo apt install libsnmp-dev
find_program(NETSNMP_CONFIG net-snmp-config)
if(NETSNMP_CONFIG)
    execute_process(
        COMMAND ${NETSNMP_CONFIG} --libs
        OUTPUT_VARIABLE NETSNMP_LIBS
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    execute_process(
        COMMAND ${NETSNMP_CONFIG} --cflags
        OUTPUT_VARIABLE NETSNMP_CFLAGS
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    separate_arguments(NETSNMP_LIBS_LIST   UNIX_COMMAND "${NETSNMP_LIBS}")
    separate_arguments(NETSNMP_CFLAGS_LIST UNIX_COMMAND "${NETSNMP_CFLAGS}")
else()
    find_library(NETSNMP_LIBS netsnmp REQUIRED)
    set(NETSNMP_CFLAGS_LIST "")
    set(NETSNMP_LIBS_LIST   ${NETSNMP_LIBS})
endif()

# --- 5. nlohmann/json --------------------------------------------------------
# Install via: sudo apt install nlohmann-json3-dev
find_package(nlohmann_json 3.2.0 QUIET)
if(NOT nlohmann_json_FOUND)
    find_path(NLOHMANN_JSON_INCLUDE_DIR nlohmann/json.hpp
        PATHS
            ${CMAKE_SOURCE_DIR}/include
            /usr/include
            /usr/local/include
        REQUIRED
    )
    target_include_directories(${PROJECT_NAME} PRIVATE ${NLOHMANN_JSON_INCLUDE_DIR})
    message(STATUS "nlohmann/json (header-only) found at: ${NLOHMANN_JSON_INCLUDE_DIR}")
endif()

# ==============================================================================
# Link Libraries
# ==============================================================================
target_include_directories(${PROJECT_NAME} PRIVATE
    ${MOSQUITTO_INCLUDE_DIR}
    ${SQLITE3_INCLUDE_DIRS}
)

target_compile_options(${PROJECT_NAME} PRIVATE
    ${SQLITE3_CFLAGS_OTHER}
    ${NETSNMP_CFLAGS_LIST}
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    ${MOSQUITTOPP_LIB}          # libmosquittopp — C++ MQTT wrapper
    ${MOSQUITTO_LIB}            # libmosquitto   — underlying C library
    ${SQLITE3_LIBRARIES}        # libsqlite3
    ${NETSNMP_LIBS_LIST}        # libnetsnmp (+ agent/helpers as reported by net-snmp-config)
    Threads::Threads            # pthreads
    $<$<TARGET_EXISTS:nlohmann_json::nlohmann_json>:nlohmann_json::nlohmann_json>
)

# ==============================================================================
# Post-build: ensure runtime directories exist
# ==============================================================================
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory
        ${CMAKE_SOURCE_DIR}/db
        ${CMAKE_SOURCE_DIR}/logs
    COMMENT "Creating db/ and logs/ runtime directories"
)

# ==============================================================================
# Install Rules
# ==============================================================================
install(TARGETS ${PROJECT_NAME} DESTINATION bin)
install(FILES   ${CMAKE_SOURCE_DIR}/config/gateway_config.json
        DESTINATION etc/iiot_gateway)

# ==============================================================================
# Build Summary
# ==============================================================================
message(STATUS "------------------------------------------------------------")
message(STATUS "Project      : ${PROJECT_NAME} v${PROJECT_VERSION}")
message(STATUS "Build type   : ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ standard : C++${CMAKE_CXX_STANDARD}")
message(STATUS "Mosquitto    : ${MOSQUITTO_LIB}")
message(STATUS "Mosquittopp  : ${MOSQUITTOPP_LIB}")
message(STATUS "SQLite3      : ${SQLITE3_LIBRARIES}")
message(STATUS "Net-SNMP     : ${NETSNMP_LIBS}")
message(STATUS "------------------------------------------------------------")