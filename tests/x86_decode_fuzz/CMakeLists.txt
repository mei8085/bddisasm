cmake_minimum_required(VERSION 3.16)

# x86 decoder integration test harness.
#
# The harness links the decoder and is built with ASAN/UBSAN when requested so
# that any read past the exact input window handed to the decoder is a hard
# error. It can also be driven entirely from the driver script
# run_x86_decode_tests.py, which does not need CMake.
project(x86_decode_fuzz LANGUAGES C)

add_executable(
    x86_decode_fuzz
    x86_decode_fuzz.c
    x86_decode_gen.c
    x86_decode_checks.c)

target_link_libraries(x86_decode_fuzz PRIVATE bddisasm::bddisasm)

target_include_directories(x86_decode_fuzz PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

set_target_properties(x86_decode_fuzz PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON)

if (NOT MSVC)
    target_compile_options(x86_decode_fuzz PRIVATE
        -Wall
        -Wextra
        -Wno-unused-parameter
        -fno-omit-frame-pointer)
endif ()

# The test is only meaningful when the decoder itself is instrumented, so make
# the sanitizers apply to this target as well.
if (BDD_ASAN)
    target_compile_options(x86_decode_fuzz PRIVATE -fsanitize=address)
    target_link_libraries(x86_decode_fuzz PRIVATE -fsanitize=address)
endif ()

if (BDD_UBSAN)
    target_compile_options(x86_decode_fuzz PRIVATE -fsanitize=undefined -fno-sanitize=alignment)
    target_link_libraries(x86_decode_fuzz PRIVATE -fsanitize=undefined -fno-sanitize=alignment)
endif ()

add_test(NAME x86_decode_fixtures COMMAND $<TARGET_FILE:x86_decode_fuzz> self-test)

add_test(NAME x86_decode_fuzz
         COMMAND $<TARGET_FILE:x86_decode_fuzz> run
                 --seed 1
                 --cases 20000
                 --report-dir ${CMAKE_CURRENT_BINARY_DIR}/report)

set_tests_properties(x86_decode_fuzz PROPERTIES
    ENVIRONMENT "ASAN_OPTIONS=detect_leaks=0")

# Convenience target that mirrors the Python driver: fixtures + a short fuzz
# run. It is not part of the default build; invoke it explicitly with
# `make decode-tests` (or `cmake --build . --target decode-tests`).
add_custom_target(decode-tests
    COMMAND $<TARGET_FILE:x86_decode_fuzz> self-test
    COMMAND $<TARGET_FILE:x86_decode_fuzz> run --seed 1 --cases 20000
            --report-dir ${CMAKE_CURRENT_BINARY_DIR}/report
    DEPENDS x86_decode_fuzz
    COMMENT "Runs the x86 decoder integration tests")
