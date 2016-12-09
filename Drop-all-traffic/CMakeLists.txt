cmake_minimum_required(VERSION 3.6)
project(Drop_all_traffic)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror")

set(SOURCE_FILES hello.c)
add_executable(Drop_all_traffic ${SOURCE_FILES})