cmake_minimum_required(VERSION 3.7)
project(libnetflow CXX)
set(default_build_type "Release")
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to '${default_build_type}' as none was specified.")
  set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE
      STRING "Choose the type of build." FORCE)
  # Set the possible values of build type for cmake-gui
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
    "Debug" "Release")
endif()

macro(exa_option OPTION_NAME OPTION_TEXT OPTION_DEFAULT)
    option(${OPTION_NAME} ${OPTION_TEXT} ${OPTION_DEFAULT})
    if(DEFINED ENV{${OPTION_NAME}})
        # Allow setting the option through an environment variable
        set(${OPTION_NAME} $ENV{${OPTION_NAME}})
    endif()
    if(${OPTION_NAME})
        add_definitions(-D${OPTION_NAME})
    endif()
    message(STATUS "  ${OPTION_NAME}: ${${OPTION_NAME}}")
endmacro()

exa_option(NETFLOW9_NO_TESTS "If ON, do not build unit tests for libnetflow9" OFF)

if(NOT NETFLOW9_NO_TESTS)
    configure_file(CMakeLists.txt.in googletest-download/CMakeLists.txt)
    execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download )
    if(result)
        message(FATAL_ERROR "CMake step for googletest failed: ${result}")
    endif()
    execute_process(COMMAND ${CMAKE_COMMAND} --build .
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download )
    if(result)
        message(FATAL_ERROR "Build step for googletest failed: ${result}")
    endif()
    add_subdirectory(${CMAKE_CURRENT_BINARY_DIR}/googletest-src
                    ${CMAKE_CURRENT_BINARY_DIR}/googletest-build
                    EXCLUDE_FROM_ALL)
endif()

include_directories(include)

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic -std=c++17")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-parameter -Wno-register -Wno-implicit-fallthrough")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wduplicated-cond -Wduplicated-branches -Wrestrict -Wnull-dereference -Wold-style-cast -Wuseless-cast -Wdouble-promotion -Wshadow -Wformat=2")
set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -ggdb -O0 -g -fdiagnostics-show-option -fprofile-arcs --coverage -ftest-coverage")
set (CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}  -O3")

FILE(GLOB CXX_SRC src/*.cpp)
FILE(GLOB CXX_HEADERS include/*/*)
file(COPY testcases DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

add_library(netflow9 SHARED ${CXX_SRC})
set_target_properties(netflow9 PROPERTIES PUBLIC_HEADER "${CXX_HEADERS}")
install(TARGETS netflow9
        LIBRARY DESTINATION lib
        PUBLIC_HEADER DESTINATION include/netflow9)
add_subdirectory(src/examples)

if(NOT NETFLOW9_NO_TESTS)
    add_subdirectory(src/unit_tests)
endif()



add_library(netflow9-refactor SHARED "src/netflow9.cpp")
add_subdirectory(test)
