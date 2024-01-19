cmake_minimum_required(VERSION 3.5.0)
project(server LANGUAGES CXX)

add_executable(server main.cpp)
set_property(TARGET server PROPERTY CXX_STANDARD 11)
target_include_directories(server PRIVATE /Users/gabo/Downloads/boost_1_82_0)
