# Setup
cmake_minimum_required(VERSION 3.22)
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(RELIB_DEBUG_DEFAULT ON)
else()
	set(RELIB_DEBUG_DEFAULT OFF)
endif()
project("ReLib" LANGUAGES C CXX VERSION 0.0.0 DESCRIPTION "Library for analyzing AMD64 PEs.")

# Compile options
option(RELIB_SHARED "Build shared libraries (.dll), off builds static libraries (.lib)" ON)
option(RELIB_DEBUG "Debug build" ${RELIB_DEBUG_DEFAULT})
set(BUILD_SHARED_LIBS ${RELIB_SHARED})

# Versioning stuff
configure_file("meta/relib.rc.in" "meta/relib.rc")

# Add to include directories
include_directories("include" "dependencies/zydis/include" "dependencies/zydis/dependencies/zycore/include")

# Zydis
option(ZYDIS_FEATURE_ENCODER "" OFF)
option(ZYDIS_FEATURE_FORMATTER "" OFF)
option(ZYDIS_BUILD_SHARED_LIB "" ${RELIB_SHARED})
add_subdirectory("dependencies/zydis")

# AsmJit
if (RELIB_SHARED)
	set(ASMJIT_EMBED OFF)
else()
	set(ASMJIT_EMBED ON)
endif()
option(ASMJIT_NO_AARCH64 "" TRUE)
option(ASMJIT_NO_FOREIGN "" TRUE)
add_subdirectory("dependencies/asmjit")

# relib
file(GLOB SOURCES
	"src/*.cpp"
	"meta/relib.rc"
)
add_library(relib ${SOURCES})
target_link_libraries(relib Zydis)
target_link_libraries(relib asmjit)
set_target_properties(relib PROPERTIES PREFIX "")
if (RELIB_SHARED)
	set_target_properties(relib PROPERTIES SUFFIX ".dll")
	target_compile_definitions(relib PUBLIC RELIB_SHARED)
else()
	set_target_properties(relib PROPERTIES SUFFIX ".lib")
endif()