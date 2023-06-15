cmake_minimum_required(VERSION 3.7)

add_executable(netflow-memory-stress test.cpp)
add_test(netflow-memory-stress netflow-memory-stress)

target_compile_features(netflow-memory-stress PRIVATE cxx_std_17)

if (NF9_USE_OWN_GTEST)
  list (APPEND GTEST_INCLUDES
    "${googletest_SOURCE_DIR}/googletest/include"
  )
endif ()

target_include_directories(netflow-memory-stress PRIVATE
  "../../src"
  "../"
  "${CMAKE_CURRENT_BINARY_DIR}/../.."
  "${GTEST_INCLUDES}"
  )
target_link_libraries(netflow-memory-stress
  netflow9
  )
