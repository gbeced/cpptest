cmake_minimum_required(VERSION 3.5.0)
project(cpptest LANGUAGES CXX)

add_executable(cpptest main.cpp)
set_property(TARGET cpptest PROPERTY CXX_STANDARD 11)
target_include_directories(cpptest PRIVATE /Users/gabo/Downloads/boost_1_82_0)
