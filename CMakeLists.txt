cmake_minimum_required(VERSION 3.7)
project(libnetflow C CXX)

option(NF9_MAKE_SHARED "If set, build a shared library version" ON)
option(NF9_BUILD_TESTS "If set, build unit tests (requires googletest)" OFF)
option(NF9_FUZZ "Enable fuzzing with LLVM fuzzer" OFF)
option(NF9_BUILD_BENCHMARK
  "If set, build benchmarks (requires google benchmark library)" OFF)
option(NF9_BUILD_EXAMPLES "If set, build examples" OFF)

include(CheckCXXCompilerFlag)
include(CheckIncludeFileCXX)

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

get_property(SRC_DIR DIRECTORY PROPERTY SOURCE_DIR)
message(STATUS "tins include:" ${SRC_DIR}/external/libtins/include/)

target_include_directories(netflow9 SYSTEM PUBLIC include
  ${SRC_DIR}/external/libtins/include/
)
target_compile_features(netflow9 PRIVATE cxx_std_17)

if (MSVC)
  message(FATAL_ERROR "MSVC support not implemented!")
else ()
  macro(nf9_add_compiler_flag flag)
    check_cxx_compiler_flag(${flag} flag-${flag})
    if(flag-${flag})
      target_compile_options(netflow9 PRIVATE ${flag})
    endif()
  endmacro()

  nf9_add_compiler_flag("-Wall")
  nf9_add_compiler_flag("-Wextra")
  nf9_add_compiler_flag("-Wpedantic")
  nf9_add_compiler_flag("-Wno-unused-parameter")
  nf9_add_compiler_flag("-Wno-register")
  nf9_add_compiler_flag("-Wno-implicit-fallthrough")
  nf9_add_compiler_flag("-Wduplicated-cond")
  nf9_add_compiler_flag("-Wduplicated-branches")
  nf9_add_compiler_flag("-Wrestrict")
  nf9_add_compiler_flag("-Wnull-dereference")
  nf9_add_compiler_flag("-Wold-style-cast")
  nf9_add_compiler_flag("-Wuseless-cast")
  nf9_add_compiler_flag("-Wdouble-promotion")
  nf9_add_compiler_flag("-Wshadow")
  nf9_add_compiler_flag("-Wformat=2")
endif ()

check_include_file_cxx("memory_resource" NF9_HAVE_MEMORY_RESOURCE)

if(NOT NF9_HAVE_MEMORY_RESOURCE)
  check_include_file_cxx("experimental/memory_resource"
    NF9_HAVE_EXPERIMENTAL_MEMORY_RESOURCE)
endif()

if(NOT NF9_HAVE_MEMORY_RESOURCE AND NOT NF9_HAVE_EXPERIMENTAL_MEMORY_RESOURCE)
  message(
    FATAL_ERROR
    "Could not find required <memory_resource> or <experimental/memory_resource> headers")
endif()

include(TestBigEndian)
test_big_endian(NF9_IS_BIG_ENDIAN)

configure_file("${PROJECT_SOURCE_DIR}/config.h.in" "${CMAKE_CURRENT_BINARY_DIR}/config.h")
target_include_directories(netflow9 PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")

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

if (NF9_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif ()
