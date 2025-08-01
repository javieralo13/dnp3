#!/usr/bin/env bash

# Every autogen.sh MUST define PLUGINNAME and PLUGINORDER. The other variables
# and functions are optional (except for the last line, where the main script
# is invoked.

# ---------------------------------------------------------------------------- #
# ------------------------------- CONFIG PART -------------------------------- #
# ---------------------------------------------------------------------------- #

# Plugin name
PLUGINNAME=dnp3

# Plugin execution order, as 3-digit decimal
PLUGINORDER=736

# Get the value of a define from a header file
#PHOME="$(dirname "$0")"
#DNP3_IP=$(perl -nle 'print $1 if /^#define\s+DNP3_IP\s+(\d+).*$/' "$PHOME/src/dnp3.h")

# Dependencies (to be copied in PLUGIN_DIR)
#if [ $DNP3_IP -eq 1 ]; then
#    EXTRAFILES=(file1 file2)
#else
#    EXTRAFILES=(file3)
#fi

# Add extra compiler flags here
#CFLAGS=""

# Add necessary libraries here using -l option
#LIBS=""

# Dependencies (use this to report missing deps)
#DEPS=""

# ---------------------------------------------------------------------------- #
# ---------------------------- DEFAULT OPTIONS ------------------------------- #
# ---------------------------------------------------------------------------- #

# Default backend to use (cmake, meson, autotools-out-of-tree, autotools)
#T2BUILD_BACKEND="cmake"

# Plugin installation directory (-p option)
#PLUGIN_DIR="$HOME/.tranalyzer/plugins"

# Compiler optimization level [0, g, 1, 2, 3, s] (-O option)
#GCCOPT="2"

# format of the compressed archive (-k option)
#PKGEXT=".tar.gz"

# Plugin installation directory (-p option)
#PLUGIN_DIR="$HOME/.tranalyzer/plugins"

# ---------------------------------------------------------------------------- #
# ------------------------ PLUGIN SPECIFIC FUNCTIONS ------------------------- #
# ---------------------------------------------------------------------------- #

# Every function (but t2_clean) MUST return 0 on success and 1 on failure.
# If no specific actions are required, all the functions can be safely removed.

# This function is called if '-c' option was used
# and can be used, e.g., to clean dependencies
#t2_clean() {
#
#}

# This function is called before building the plugin
# and can be used, e.g., to build dependencies
#t2_prebuild() {
#    return 0
#}

# This function is called before the plugin and EXTRAFILES have been installed
#t2_preinst() {
#    return 0
#}

# This function is called for each file in EXTRAFILES and replaces the standard
# installation function, i.e., copy (gunzip'd) file to $PLUGIN_DIR.
# Return 2 to fallback to the standard installation function.
#t2_inst() {
#    FILE="$1"
#    return 0
#}

# This function is called after the plugin and EXTRAFILES have been installed
#t2_postinst() {
#    return 0
#}

# This function is called before the plugin has been packaged
# (can be used, e.g., to package the latest version of a database)
#t2_prepackage() {
#    return 0
#}

# This function is called when autogen.sh -U option is used
# (can be used, e.g., to download the latest version of a blacklist)
#t2_update() {
#    return 1
#}

# ---------------------------------------------------------------------------- #
# ----------------- INVOKE THE MAIN AUTOGEN (DO NOT REMOVE) ------------------ #
# ---------------------------------------------------------------------------- #

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
