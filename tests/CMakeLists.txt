cmake_minimum_required(VERSION 3.10)

# Add Unity source file (assuming it's in vendor/unity/src)
add_library(unity STATIC vendor/unity/src/unity.c)
target_include_directories(unity PUBLIC vendor/unity/src)

# Placeholder for actual test executables
# Example:
# add_executable(test_runner test_runner.c test_utils.c ...)
# target_link_libraries(test_runner PRIVATE easy_cpace unity)
# add_test(NAME RunCoreTests COMMAND test_runner)

message(STATUS "Test configuration placeholder loaded.")
