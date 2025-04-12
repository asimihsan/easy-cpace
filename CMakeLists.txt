cmake_minimum_required(VERSION 3.30)
project(cpace C)

set(CMAKE_C_STANDARD 99)

add_library(cpace SHARED library.c)
