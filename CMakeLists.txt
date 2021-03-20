cmake_minimum_required(VERSION 2.8.9)
project(nlk)

include_directories(/usr/local/ACE_TAO-6.5.11/include)
link_directories(/usr/local/ACE_TAO-6.5.11/lib)

#Adding Complier flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -g -Wall -Wextra")

#However, the file(GLOB...) allows for wildcard additions:
file(GLOB SOURCES "*.cc")

add_executable(NLINK ${SOURCES})
target_link_libraries(NLINK ACE)


