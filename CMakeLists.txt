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
message(STATUS "RELIB_SHARED = ${RELIB_SHARED}")
message(STATUS "RELIB_DEBUG = ${RELIB_DEBUG}")

# Versioning stuff
configure_file("meta/relib.rc.in" "meta/relib.rc")

# Zydis
option(ZYDIS_FEATURE_ENCODER "" OFF)
option(ZYDIS_FEATURE_FORMATTER "" ON)
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
file(GLOB RELIB_SOURCES
	"src/*.cpp"
	"meta/relib.rc"
)
add_library(relib ${RELIB_SOURCES})
target_include_directories(relib AFTER PUBLIC "include")
target_link_libraries(relib Zydis asmjit)
set_target_properties(relib PROPERTIES PREFIX "")
if (RELIB_SHARED)
	set_target_properties(relib PROPERTIES SUFFIX ".dll")
	target_compile_definitions(relib PUBLIC RELIB_SHARED)
else()
	set_target_properties(relib PROPERTIES SUFFIX ".lib")
endif()

# Strip debugging information
if (DEFINED CMAKE_STRIP AND NOT RELIB_DEBUG AND RELIB_SHARED)
	#add_custom_command(TARGET Zydis POST_BUILD COMMAND objcopy --only-keep-debug $<TARGET_FILE:Zydis> "bin/${CMAKE_BUILD_TYPE}/Zydis.dbg" COMMAND ${CMAKE_STRIP} $<TARGET_FILE:Zydis>)
	#add_custom_command(TARGET asmjit POST_BUILD COMMAND objcopy --only-keep-debug $<TARGET_FILE:asmjit> "bin/${CMAKE_BUILD_TYPE}/asmjit.dbg" COMMAND ${CMAKE_STRIP} $<TARGET_FILE:asmjit>)
	#add_custom_command(TARGET relib POST_BUILD COMMAND objcopy --only-keep-debug $<TARGET_FILE:relib> "bin/${CMAKE_BUILD_TYPE}/relib.dbg" COMMAND ${CMAKE_STRIP} $<TARGET_FILE:relib>)
endif()