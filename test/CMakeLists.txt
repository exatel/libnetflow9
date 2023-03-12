cmake_minimum_required(VERSION 3.7)

enable_testing()
find_package(GTest REQUIRED)

get_property(SRC_DIR DIRECTORY PROPERTY SOURCE_DIR)
message(STATUS "tins libs:" ${SRC_DIR}/../../libtins/build/lib/)
find_library(LIBTINS_LIBRARIES tins ${SRC_DIR}/../../libtins/build/lib/)

file(GLOB src *.cpp)
add_executable(netflowtests ${src})
add_test(netflowtests netflowtests)

target_compile_features(netflowtests PRIVATE cxx_std_17)
target_include_directories(netflowtests PRIVATE
  "../src"
  "${GTEST_INCLUDE_DIRS}"
  "${CMAKE_CURRENT_BINARY_DIR}/.."
  )
target_link_libraries(netflowtests
  netflow9
  GTest::GTest
  GTest::Main
  "${LIBTINS_LIBRARIES}"
  )

add_subdirectory(memory-stress-test)
