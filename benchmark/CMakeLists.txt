cmake_minimum_required(VERSION 3.7)

file(GLOB src *.cpp)
add_executable(netflow-benchmark ${src})

find_package(benchmark REQUIRED)

target_compile_features(netflow-benchmark PRIVATE cxx_std_17)
target_link_libraries(netflow-benchmark netflow9 benchmark::benchmark_main)
target_include_directories(netflow-benchmark PRIVATE
  "${PROJECT_SOURCE_DIR}/src"
  "${PROJECT_SOURCE_DIR}/test"
  "${PROJECT_BINARY_DIR}"
  )
