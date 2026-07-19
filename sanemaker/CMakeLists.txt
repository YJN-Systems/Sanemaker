add_library(sanemaker SHARED src/sanemaker.cpp src/metadata.cpp src/code_range.cpp src/target_range.cpp src/access_log.cpp)

find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB REQUIRED glib-2.0)

target_include_directories(sanemaker PRIVATE
	${GLIB_INCLUDE_DIRS}
	include
)

target_compile_definitions(sanemaker PRIVATE
	QEMU_PLUGIN_HDR="${QEMU_PLUGIN_HDR}"
)

target_compile_options(sanemaker PRIVATE
	${GLIB_CFLAGS_OTHER}
	-Wall -Wextra -Wpedantic
)

target_link_libraries(sanemaker PRIVATE
	${GLIB_LIBRARIES}
)

target_compile_features(sanemaker PRIVATE cxx_std_17)

set_target_properties(sanemaker PROPERTIES
	PREFIX ""
	OUTPUT_NAME "sanemaker"
	SUFFIX ".so"
)
