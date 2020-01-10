cmake_minimum_required(VERSION 3.7)

enable_testing()
find_package(GTest REQUIRED)

find_library(LIBTINS_LIBRARIES tins)

file(GLOB src *.cpp)
add_executable(netflowtests ${src})
add_test(netflowtests netflowtests)

target_include_directories(netflowtests PRIVATE
  "../include"
  "../src"
  "${GTEST_INCLUDE_DIRS}"
  )
target_link_libraries(netflowtests
  netflow9
  GTest::GTest
  GTest::Main
  "${LIBTINS_LIBRARIES}"
  )
