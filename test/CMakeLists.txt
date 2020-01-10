cmake_minimum_required(VERSION 3.7)

enable_testing()
find_package(GTest REQUIRED)

# Find libtins
find_package(PkgConfig)
if (PKG_CONFIG_FOUND)
  pkg_check_modules(LIBTINS REQUIRED libtins)
else()
  set(LIBTINS_LIBRARIES "tins")
endif()

file(GLOB src *.cpp)
add_executable(netflowtests ${src})
add_test(netflowtests netflowtests)

target_link_directories(netflowtests PRIVATE
  ${LIBTINS_LIBRARY_DIRS}
  )
target_include_directories(netflowtests PRIVATE
  "../include"
  "../src"
  "${GTEST_INCLUDE_DIRS}"
  "${LIBTINS_INCLUDE_DIRS}"
  )
target_link_libraries(netflowtests
  netflow9
  GTest::GTest
  GTest::Main
  "${LIBTINS_LIBRARIES}"
  )
