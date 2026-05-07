cmake_minimum_required(VERSION 3.18)
project(python_modsecurity LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(Python COMPONENTS Interpreter Development.Module REQUIRED)
find_package(pybind11 CONFIG REQUIRED)

if(NOT MODSECURITY_ROOT AND DEFINED ENV{MODSECURITY_ROOT})
    set(MODSECURITY_ROOT "$ENV{MODSECURITY_ROOT}")
endif()

find_path(MODSECURITY_INCLUDE_DIR
    NAMES modsecurity/modsecurity.h
    HINTS
        ${MODSECURITY_ROOT}/include
        /opt/modsecurity/include
        /usr/local/modsecurity/include
        /usr/local/include
        /usr/include
)

find_library(MODSECURITY_LIBRARY
    NAMES modsecurity
    HINTS
        ${MODSECURITY_ROOT}/lib
        ${MODSECURITY_ROOT}/lib64
        /opt/modsecurity/lib
        /opt/modsecurity/lib64
        /usr/local/modsecurity/lib
        /usr/local/lib
        /usr/lib
)

if(NOT MODSECURITY_INCLUDE_DIR OR NOT MODSECURITY_LIBRARY)
    message(FATAL_ERROR
        "libmodsecurity not found. Install it from "
        "https://github.com/owasp-modsecurity/ModSecurity, or pass "
        "-DMODSECURITY_ROOT=/path/to/install.")
endif()

message(STATUS "Found libmodsecurity: ${MODSECURITY_LIBRARY}")
message(STATUS "Found libmodsecurity headers: ${MODSECURITY_INCLUDE_DIR}")

pybind11_add_module(_libmodsecurity src/bindings.cpp)
target_include_directories(_libmodsecurity PRIVATE ${MODSECURITY_INCLUDE_DIR})
target_link_libraries(_libmodsecurity PRIVATE ${MODSECURITY_LIBRARY})

get_filename_component(MODSECURITY_LIBRARY_DIR ${MODSECURITY_LIBRARY} DIRECTORY)
if(APPLE)
    set(_origin_token "@loader_path")
else()
    set(_origin_token "$ORIGIN")
endif()
set_target_properties(_libmodsecurity PROPERTIES
    INSTALL_RPATH "${_origin_token};${MODSECURITY_LIBRARY_DIR}"
    BUILD_WITH_INSTALL_RPATH TRUE
)

install(TARGETS _libmodsecurity LIBRARY DESTINATION libmodsecurity)
