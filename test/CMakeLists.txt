cmake_minimum_required(VERSION 3.7)

enable_testing()
if (NOT NF9_USE_OWN_GTEST)
    find_package(GTest REQUIRED)
    list (APPEND GTEST_LIBRARIES
        GTest::GTest
        GTest::Main
    )
else()
    include(FetchContent)
    FetchContent_Declare(
        googletest
        # Specify the commit you depend on and update it regularly.
        URL https://github.com/google/googletest/archive/refs/tags/v1.13.0.zip
    )
    # For Windows: Prevent overriding the parent project's
    # compiler/linker settings
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
    list (APPEND GTEST_LIBRARIES
        gtest_main
    )
endif()

if (NOT NF9_USE_OWN_LIBTINS)
    find_library(LIBTINS_LIBRARIES tins)
else()
    get_property(SRC_DIR DIRECTORY PROPERTY SOURCE_DIR)
    find_library(LIBTINS_LIBRARIES tins 
      ${SRC_DIR}/../external/libtins/build/lib/)
endif()

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
  "${GTEST_LIBRARIES}"
  "${LIBTINS_LIBRARIES}"
  )

add_subdirectory(memory-stress-test)
