cmake_minimum_required(VERSION 3.7)
project(libnetflow CXX)

option(NF9_MAKE_SHARED "If set, build a shared library version" ON)
option(NF9_BUILD_TESTS "If set, build unit tests (requires googletest)" ON)
option(NF9_FUZZ "Enable fuzzing with LLVM fuzzer" OFF)
option(NF9_BUILD_BENCHMARK
  "If set, build benchmarks (requires google benchmark library)" OFF)

if (NOT CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE STREQUAL "")
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "" FORCE)
endif()

file(GLOB CXX_SRC src/*.cpp)
file(GLOB CXX_HEADERS include/*/*)
file(COPY testcases DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

if (NF9_MAKE_SHARED)
  add_library(netflow9 SHARED ${CXX_SRC})
  set_target_properties(netflow9 PROPERTIES
    PUBLIC_HEADER "${CXX_HEADERS}"
    DEFINE_SYMBOL "NF9_BUILD")
  target_compile_options(netflow9 PRIVATE "-fvisibility=hidden")
else ()
  add_library(netflow9 STATIC ${CXX_SRC})
endif ()

target_include_directories(netflow9 SYSTEM PUBLIC include)
target_compile_features(netflow9 PUBLIC cxx_std_17)

if (MSVC)
  message(FATAL_ERROR "MSVC support not implemented!")
else ()
  target_compile_options(netflow9 PRIVATE
    "-Wall"
    "-Wextra"
    "-Wpedantic"
    "-Wno-unused-parameter"
    "-Wno-register"
    "-Wno-implicit-fallthrough"
    "-Wduplicated-cond"
    "-Wduplicated-branches"
    "-Wrestrict"
    "-Wnull-dereference"
    "-Wold-style-cast"
    "-Wuseless-cast"
    "-Wdouble-promotion"
    "-Wshadow"
    "-Wformat=2"
  )
endif ()

install(TARGETS netflow9
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        PUBLIC_HEADER DESTINATION include/netflow9)

if (NF9_BUILD_TESTS)
  add_subdirectory(test)
endif ()

if (NF9_BUILD_BENCHMARK)
  add_subdirectory(benchmark)
endif()

if (NF9_FUZZ)
  add_subdirectory(fuzz)
endif ()
