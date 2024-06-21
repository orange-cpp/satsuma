cmake_minimum_required(VERSION 3.28)
project(mmap)

set(CMAKE_CXX_STANDARD 26)


add_executable(satsuma main.cpp)
add_subdirectory(source)

target_include_directories(satsuma PUBLIC include)
target_link_options(satsuma PRIVATE /MAP:satsuma.map)