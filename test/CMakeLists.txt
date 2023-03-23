cmake_minimum_required(VERSION 3.7)

enable_testing()
include(FetchContent)
FetchContent_Declare(
  googletest
  # Specify the commit you depend on and update it regularly.
  URL https://github.com/google/googletest/archive/refs/tags/v1.13.0.zip
  # FIND_PACKAGE_ARGS NAMES GTest
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)
# Content googletest already populated in FetchContent_Populate(googletest)
# find_package(GTest REQUIRED)

message(STATUS "googletest populate: " ${googletest_SOURCE_DIR} " " ${googletest_BINARY_DIR})

get_property(SRC_DIR DIRECTORY PROPERTY SOURCE_DIR)
message(STATUS "tins libs: " ${SRC_DIR}/../external/libtins/build/lib/)
find_library(LIBTINS_LIBRARIES tins ${SRC_DIR}/../external/libtins/build/lib/)

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
  # GTest::GTest
  gtest_main
  "${LIBTINS_LIBRARIES}"
  )

add_subdirectory(memory-stress-test)
