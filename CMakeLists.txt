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

# Sanitizer builds: cmake -DSTACK_SANITIZE=address (ASan + UBSan) or =thread (TSan).
# Use a separate build directory for each.
set(STACK_SANITIZE "" CACHE STRING "Sanitizer for all targets: '', 'address' or 'thread'")
if(STACK_SANITIZE STREQUAL "address")
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=address,undefined)
elseif(STACK_SANITIZE STREQUAL "thread")
  add_compile_options(-fsanitize=thread -g)
  add_link_options(-fsanitize=thread)
elseif(NOT STACK_SANITIZE STREQUAL "")
  message(FATAL_ERROR "STACK_SANITIZE must be empty, 'address' or 'thread'")
endif()

# ---- Source files ----
# Stack source files shared by the main executable and the tests.
# time_now.c and random.c are not in this list: the tests link replacements for them
# (a controllable clock and drop rate), see tests/fakes.
set(STACK_SOURCES
  src/api.c  
  src/app.c
  src/arp.c
  src/buffer_pool.c
  src/byte_ring_buffers.c
  src/checksum.c
  src/constants.c
  src/ethernet.c
  src/hash.c
  src/heap.c
  src/icmp.c
  src/ipv4.c
  src/layer_router.c
  src/nw_interface.c
  src/ping_test.c
  src/pkt_ring_buffer.c
  src/queue.c
  src/routing_table.c
  src/socket_manager.c
  src/sockfd_manager.c
  src/stack_constructor.c
  src/stack_tx_worker.c
  src/syn_cookie.c
  src/tap.c
  src/tcp.c
  src/tcp_conn_socket.c
  src/tcp_conn_htable.c
  src/tcp_listener_htable.c
  src/tcp_listener_socket.c
  src/tcp_options.c
  src/tcp_segment.c
  src/timer.c
  src/timer_worker.c
  src/udp.c
  src/udp_hashtable.c
  src/udp_socket.c
  src/window_helpers.c
)

set(LIB_SOURCES
  ${STACK_SOURCES}
  src/random.c
  src/time_now.c
)

# Main executable source files
set(MAIN_SOURCES
  ${LIB_SOURCES}
  src/main.c
)

# ---- Main executable ----
add_executable(networking ${MAIN_SOURCES})
target_compile_options(networking PRIVATE -Wall -Wextra -rdynamic)

# ---- Tests ----
# unit_tests:   one stack, no threads, fake clock; the test plays the remote peer
# system_tests: two stacks on their real threads, connected by a simulated lossy link
# interop_peer: the stack on tap0, driven by tests/interop/run_interop.sh against Linux
if(BUILD_TESTING)
  include(CTest)
  include(FetchContent)

  FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
  )

  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)

  set(TEST_SUPPORT_SOURCES
    tests/support/harness.c
    tests/support/wire.cpp
    tests/support/test_main.cpp
    tests/fakes/fake_random.c
  )
  set(TEST_INCLUDE_DIRS
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/tests/support
    ${CMAKE_SOURCE_DIR}/tests/fakes
    ${CMAKE_SOURCE_DIR}/tests/unit
    ${CMAKE_SOURCE_DIR}/tests/system
  )

  file(GLOB UNIT_TEST_FILES CONFIGURE_DEPENDS tests/unit/*.cpp)
  add_executable(unit_tests EXCLUDE_FROM_ALL
    ${STACK_SOURCES} ${TEST_SUPPORT_SOURCES} tests/fakes/fake_time.c ${UNIT_TEST_FILES})

  file(GLOB SYSTEM_TEST_FILES CONFIGURE_DEPENDS tests/system/*.cpp)
  add_executable(system_tests EXCLUDE_FROM_ALL
    ${STACK_SOURCES} ${TEST_SUPPORT_SOURCES} src/time_now.c ${SYSTEM_TEST_FILES})

  foreach(t unit_tests system_tests)
    target_include_directories(${t} PRIVATE ${TEST_INCLUDE_DIRS})
    target_compile_options(${t} PRIVATE -Wall -Wextra)
    target_link_libraries(${t} PRIVATE GTest::gtest pthread)
  endforeach()

  add_executable(interop_peer EXCLUDE_FROM_ALL
    ${STACK_SOURCES} src/time_now.c tests/fakes/fake_random.c tests/interop/interop_peer.c)
  target_include_directories(interop_peer PRIVATE ${TEST_INCLUDE_DIRS})
  target_compile_options(interop_peer PRIVATE -Wall -Wextra)
  target_link_libraries(interop_peer PRIVATE pthread)

  # builds both suites and runs every test in its own process, so a hang or crash in
  # one test can't take the others with it: cmake --build build --target check
  add_custom_target(check
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -j 4
    DEPENDS unit_tests system_tests
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    USES_TERMINAL)

  include(GoogleTest)
  gtest_discover_tests(unit_tests DISCOVERY_MODE PRE_TEST PROPERTIES TIMEOUT 60)
  gtest_discover_tests(system_tests DISCOVERY_MODE PRE_TEST PROPERTIES TIMEOUT 600)
endif()

# ---- Formatting ----
find_program(CLANG_FORMAT clang-format REQUIRED)

file(GLOB_RECURSE ALL_SOURCE_FILES
     CONFIGURE_DEPENDS
     ${CMAKE_SOURCE_DIR}/src/*.c
     ${CMAKE_SOURCE_DIR}/src/*.h
)

add_custom_target(format
  COMMAND ${CLANG_FORMAT} -style=file -i ${ALL_SOURCE_FILES}
)

add_custom_target(check-format
  COMMAND ${CLANG_FORMAT} -style=file --dry-run --Werror ${ALL_SOURCE_FILES}
)
