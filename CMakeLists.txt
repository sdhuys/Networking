cmake_minimum_required(VERSION 3.14)
project(networking LANGUAGES C CXX)

# ---- Policy ----
cmake_policy(SET CMP0135 NEW)

# ---- Language standards ----
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---- Options ----
option(BUILD_TESTING "Build tests" ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ---- Source files ----
# Library source files (shared between main executable and tests)
set(LIB_SOURCES
  src/app.c
  src/arp.c
  src/buffer_pool.c
  src/checksum.c
  src/constants.c
  src/ethernet.c
  src/icmp.c
  src/ipv4.c
  src/layer_router.c
  src/ring_buffer.c
  src/routing_table.c
  src/socket_manager.c
  src/stack_constructor.c
  src/stack_tx_worker.c
  src/tap.c
  src/timer.c
  src/tcp.c
  src/udp.c
  src/udp_hashtable.c
  src/udp_socket.c
)

# Main executable source files
set(MAIN_SOURCES
  ${LIB_SOURCES}
  src/main.c
)

# Test source files (excludes main.c to avoid conflict with gtest_main)
set(TEST_SOURCES
  ${LIB_SOURCES}
)

# ---- Main executable ----
add_executable(networking.elf ${MAIN_SOURCES})
target_compile_options(networking.elf PRIVATE -Wall -Wextra -rdynamic)

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
  file(GLOB TEST_FILES "tests/*.cpp")
  add_executable(networking_tests EXCLUDE_FROM_ALL ${TEST_FILES} ${TEST_SOURCES})
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
