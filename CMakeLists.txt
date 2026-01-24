cmake_minimum_required(VERSION 3.14)
project(networking LANGUAGES C CXX)

# ---- Language standards ----
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---- Options ----
option(BUILD_TESTING "Build tests" ON)

# ---- Main executable ----
file(GLOB SRC_FILES CONFIGURE_DEPENDS src/*.c)
add_executable(networking.elf ${SRC_FILES})
target_compile_options(networking.elf PRIVATE -Wall -Wextra)

# ---- Tests ----
if(BUILD_TESTING)
  include(CTest)
  include(FetchContent)

  FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
  )

  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)

  add_executable(networking_tests tests/hello_test.cpp ${SRC_FILES})
  target_include_directories(networking_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)
  target_compile_options(networking_tests PRIVATE -Wall -Wextra)

  target_link_libraries(networking_tests
    PRIVATE GTest::gtest GTest::gtest_main
  )

  include(GoogleTest)
  gtest_discover_tests(networking_tests)
endif()

# ---- Formatting ----
find_program(CLANG_FORMAT clang-format)
if(CLANG_FORMAT)
  file(GLOB_RECURSE ALL_SOURCE_FILES
    src/*.c
    src/*.h
  )

  add_custom_target(format
    COMMAND ${CLANG_FORMAT} -i ${ALL_SOURCE_FILES}
    COMMENT "Running clang-format on all source files"
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  )

  add_custom_target(check-format
    COMMAND ${CLANG_FORMAT} --dry-run --Werror ${ALL_SOURCE_FILES}
    COMMENT "Checking if source files are formatted correctly"
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  )
else()
  message(WARNING "clang-format not found. Format targets will not be available.")
endif()
