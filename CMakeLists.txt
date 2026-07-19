cmake_minimum_required(VERSION 3.21)

project(Sanemaker LANGUAGES C CXX)

option(SANEMAKER_BUILD_TRAPS_LIB "Build sanemaker static library" ON)

option(SANEMAKER_BUILD_QEMU_PLUGIN "Build QEMU TCG plugin" ${PROJECT_IS_TOP_LEVEL})

if(SANEMAKER_BUILD_TRAPS_LIB)
	add_subdirectory(libtraps)
endif()

if(SANEMAKER_BUILD_QEMU_PLUGIN)
	set(QEMU_PLUGIN_HDR "" CACHE PATH "Path to qemu-plugin.h")

	if(NOT QEMU_PLUGIN_HDR)
		message(FATAL_ERROR
			"QEMU_PLUGIN_HDR must be set when building the QEMU plugin.")
	endif()

	add_subdirectory(sanemaker)
endif()

