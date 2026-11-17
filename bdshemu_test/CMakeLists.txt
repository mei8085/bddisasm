cmake_minimum_required(VERSION 3.16)

# Integration tests for the x86 emulator that drive the public bdshemu API directly instead of
# comparing disasmtool output. They are built when BDD_INCLUDE_TESTS is on and are run by the
# `test` target defined in disasmtool/CMakeLists.txt, together with the result-comparison suite.

add_executable(bdshemu_selfmod_test integration/selfmod_test.c)
target_link_libraries(bdshemu_selfmod_test PRIVATE bddisasm::bdshemu)
set_target_properties(bdshemu_selfmod_test PROPERTIES C_STANDARD 11)

if (MSVC)
    target_compile_options(bdshemu_selfmod_test PRIVATE /W4)
else ()
    target_compile_options(bdshemu_selfmod_test PRIVATE
        -Wall
        -Wextra
        -Wshadow
        -Wstrict-prototypes
        -Wwrite-strings
        -Winit-self
        -Wnull-dereference
        -fno-strict-aliasing
        -fwrapv)
endif ()
