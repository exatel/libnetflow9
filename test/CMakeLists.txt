cmake_minimum_required(VERSION 3.7)
set(COVERAGE OFF CACHE BOOL "Coverage")

enable_testing()
find_package(GTest)
include_directories(${GTEST_INCLUDE_DIRS})
include_directories(../include)

if(UNIX AND NOT APPLE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread -rdynamic -Wl,--no-as-needed -ldl")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread -rdynamic -Wl,-soname -ldl")
endif()

file(GLOB src *.cpp)
add_executable(netflowtests ${src})

add_test(netflowtests netflowtests)
target_link_libraries(netflowtests netflow9 gtest gtest_main pthread tins)
add_test(NAME runUnitTests COMMAND netflowtests)
