cmake_minimum_required(VERSION 3.7)
project(libnetflow CXX)

include_directories(include)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic -std=c++17")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-parameter -Wno-register -Wno-implicit-fallthrough")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wduplicated-cond -Wduplicated-branches -Wrestrict -Wnull-dereference -Wold-style-cast -Wuseless-cast -Wdouble-promotion -Wshadow -Wformat=2")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -ggdb -O0 -g -fdiagnostics-show-option -fprofile-arcs --coverage -ftest-coverage")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}  -O3")

file(GLOB CXX_SRC src/*.cpp)
file(GLOB CXX_HEADERS include/*/*)
file(COPY testcases DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

add_library(netflow9 SHARED ${CXX_SRC})
set_target_properties(netflow9 PROPERTIES PUBLIC_HEADER "${CXX_HEADERS}")
install(TARGETS netflow9
        LIBRARY DESTINATION lib
        PUBLIC_HEADER DESTINATION include/netflow9)

add_subdirectory(test)
