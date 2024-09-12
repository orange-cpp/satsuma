cmake_minimum_required(VERSION 3.28)
project(mmap)

set(CMAKE_CXX_STANDARD 26)

add_library(satsuma source/ManualMapInjector.cpp)

add_subdirectory(source)

target_include_directories(satsuma PUBLIC include)