add_library(saneapi INTERFACE)
add_library(sanemaker::api ALIAS saneapi)

target_include_directories(saneapi
	INTERFACE
		${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_library(sanetraps STATIC src/traps.c)
add_library(sanemaker::traps ALIAS sanetraps)

target_link_libraries(sanetraps
	PUBLIC
		saneapi
)

target_compile_definitions(sanetraps PRIVATE SANEMAKER)

set_target_properties(sanetraps PROPERTIES
	OUTPUT_NAME sanetraps
	POSITION_INDEPENDENT_CODE TRUE
)
