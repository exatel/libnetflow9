cmake_minimum_required(VERSION 3.7)

if (NOT CMAKE_CXX_COMPILER MATCHES "clang")
  message(FATAL_ERROR "Fuzzing is only supported with clang compiler")
endif()

file(GLOB src *.cpp)
add_executable(netflowfuzz ${src})

target_compile_features(netflowfuzz PRIVATE cxx_std_17)
target_include_directories(netflowfuzz PRIVATE
  "../src"
  )
target_link_libraries(netflowfuzz netflow9)
target_compile_options(netflowfuzz PRIVATE "-fsanitize=fuzzer,address,undefined")
target_link_options(netflowfuzz PRIVATE "-fsanitize=fuzzer,address,undefined")
