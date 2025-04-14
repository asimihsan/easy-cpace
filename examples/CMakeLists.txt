# cpace/examples/CMakeLists.txt
cmake_minimum_required(VERSION 3.10) # Keep minimum version reasonable

# Find the package created by the root CMakeLists.txt
# This is generally not needed if adding subdirectory directly,
# but good practice if examples were separate.
# find_package(EasyCPace REQUIRED) # Not needed here because it's built together

# Add the basic exchange example executable
add_executable(basic_exchange basic_exchange.c)

# Link the example against the easy_cpace library target
# The easy_cpace target (alias for easy_cpace_core) should handle
# linking its own dependencies (like monocypher_lib) publicly.
target_link_libraries(basic_exchange PRIVATE easy_cpace)

# Optionally, ensure include directories are available if needed,
# though linking should handle this via INTERFACE properties.
# target_include_directories(basic_exchange PRIVATE
#    $<TARGET_PROPERTY:easy_cpace,INTERFACE_INCLUDE_DIRECTORIES>
# )

# Add compile definition for debug logging if enabled globally
if(CPACE_ENABLE_DEBUG_LOGGING)
    target_compile_definitions(basic_exchange PRIVATE CPACE_DEBUG_LOG)
endif()


message(STATUS "Configured basic_exchange example.")

# Add more examples here following the same pattern:
# add_executable(another_example another_example.c)
# target_link_libraries(another_example PRIVATE easy_cpace)
