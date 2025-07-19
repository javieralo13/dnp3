cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

# If your plugin has only one file named src/pluginName.c,
# then this is the only line you need to change.
set(_plugin_name dnp3)
#set(_plugin_number 999)

project(${_plugin_name}
    HOMEPAGE_URL "https://tranalyzer.com"
    VERSION      0.9.3
    LANGUAGES    C
)

# ---------------------------------------------------------------------------- #
# Find libraries                                                               #
# ---------------------------------------------------------------------------- #

#find_package(Threads REQUIRED)
#find_package(Threads QUIET)

#find_package(PkgConfig REQUIRED)
#pkg_check_modules(MY_NAME REQUIRED module_name)

# ---------------------------------------------------------------------------- #
# Source files                                                                 #
# ---------------------------------------------------------------------------- #

add_library(${_plugin_name}
    MODULE
        src/${_plugin_name}.c
        #../../utils/t2buf.c
)

# ---------------------------------------------------------------------------- #
# C standard to use                                                            #
# ---------------------------------------------------------------------------- #

set_target_properties(${_plugin_name}
    PROPERTIES
        C_STANDARD          99
        C_EXTENSIONS        ON
        C_STANDARD_REQUIRED ON
)

# ---------------------------------------------------------------------------- #
# Include directories (-I ...)                                                 #
# ---------------------------------------------------------------------------- #

target_include_directories(${_plugin_name}
    PRIVATE
        ../../utils
        ../../tranalyzer2/src
        #../tcpFlags/src        # tell the compiler where to find header
                                # files from dependent plugins
        #${MY_NAME_INCLUDE_DIRS}
)

# ---------------------------------------------------------------------------- #
# Compile options                                                              #
# ---------------------------------------------------------------------------- #

target_compile_options(${_plugin_name}
    PRIVATE
        -Wall
        -Wextra
        -Wundef
)

# ---------------------------------------------------------------------------- #
# Compile definitions (-D ...)                                                 #
# ---------------------------------------------------------------------------- #

set(_pwd "${CMAKE_CURRENT_SOURCE_DIR}")
cmake_path(APPEND _header_file "${_pwd}" "src" "${_plugin_name}.h")

target_compile_definitions(${_plugin_name}
    PRIVATE
        PLUGIN_SRCH="${_header_file}"
        #PLUGIN_NUMBER="${_plugin_number}"
)

if (APPLE)
    target_compile_definitions(${_plugin_name}
        PRIVATE
            _DARWIN_C_SOURCE
    )
    set_target_properties(${_plugin_name}
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
elseif (UNIX)
    target_compile_definitions(${_plugin_name}
        PRIVATE
            _GNU_SOURCE
    )
endif()

# ---------------------------------------------------------------------------- #
# Libraries (-l ..., -L)                                                       #
# ---------------------------------------------------------------------------- #

#target_link_libraries(${_plugin_name}
#    PRIVATE
#        m
#        ${MY_NAME_LIBRARIES}
#        ${MY_NAME_LDFLAGS}
#)

# ---------------------------------------------------------------------------- #
# Installation                                                                 #
# ---------------------------------------------------------------------------- #

set_target_properties(${_plugin_name}
    PROPERTIES
        #PREFIX      ""
        #OUTPUT_NAME "${_plugin_number}_${_plugin_name}"
        OUTPUT_NAME "${_plugin_name}"
        SUFFIX      ".so"
)
