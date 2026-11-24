cmake_minimum_required(VERSION 3.16)
project(radpriv VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

option(RADPRIV_BUILD_TESTS "Build the test suite" ON)
option(RADPRIV_BUILD_CLI "Build the CLI tools" ON)
option(RADPRIV_WERROR "Treat warnings as errors" OFF)

add_library(radpriv STATIC
  src/common.cpp
  src/sha256.cpp
  src/ed25519.cpp
  src/aead.cpp
  src/event.cpp
  src/envelope.cpp
  src/ledger.cpp
  src/policy.cpp
  src/journal.cpp
  src/attest.cpp
  src/bundle.cpp
  src/session.cpp
  src/synth.cpp
)
target_include_directories(radpriv PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(radpriv PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(radpriv PRIVATE -Wall -Wextra -Wpedantic)
  if(RADPRIV_WERROR)
    target_compile_options(radpriv PRIVATE -Werror)
  endif()
endif()

if(RADPRIV_BUILD_CLI)
  add_executable(radpriv-cli apps/radpriv_cli.cpp)
  target_link_libraries(radpriv-cli PRIVATE radpriv)
  set_target_properties(radpriv-cli PROPERTIES OUTPUT_NAME radpriv)
endif()

if(RADPRIV_BUILD_TESTS)
  enable_testing()
  add_executable(radpriv_tests
    tests/test_main.cpp
    tests/test_crypto.cpp
    tests/test_ledger.cpp
    tests/test_envelope.cpp
    tests/test_attest.cpp
    tests/test_journal.cpp
  )
  target_link_libraries(radpriv_tests PRIVATE radpriv)
  target_include_directories(radpriv_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
  add_test(NAME radpriv_tests COMMAND radpriv_tests)

  add_executable(radpriv_sim apps/sim.cpp)
  target_link_libraries(radpriv_sim PRIVATE radpriv)
  add_test(NAME radpriv_sim_fall COMMAND radpriv_sim fall)
endif()
