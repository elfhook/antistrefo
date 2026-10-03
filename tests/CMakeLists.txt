# tests/CMakeLists.txt - CTest targets, one per suite, each printing only on failure.
# Module: test (CMake).
# Owns: the utility correctness suite and its runtime library setting.
# Depends: re_utils. The style and format gates are registered in the root file.
add_executable(re_test_utils test_utils.c test_features.c)
target_link_libraries(re_test_utils PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_utils
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_utils PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME utils COMMAND re_test_utils)

# The decoder suite is a separate binary so a length regression names itself in
# the CTest output instead of hiding inside the utility suite.
add_executable(re_test_disasm test_disasm.c)
target_link_libraries(re_test_disasm PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_disasm
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_disasm PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME disasm COMMAND re_test_disasm)

# The layout suite is separate for the same reason: a box that is one column short
# should name itself in the CTest output rather than hiding in the utility counts.
add_executable(re_test_tui test_tui.c)
target_link_libraries(re_test_tui PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_tui
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_tui PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME tui COMMAND re_test_tui)

# The screen grid and the reference arrangement. Named separately because a layout
# that has silently stopped composing looks exactly like a layout that never ran.
add_executable(re_test_screen test_screen.c)
target_link_libraries(re_test_screen PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_screen
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_screen PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME screen COMMAND re_test_screen)

# The interactive front end's pure half: the event decoder, the focus order, and the
# frame diff. The platform file is deliberately absent, because a test that needs a
# terminal is a test that only runs on somebody's machine.
add_executable(re_test_input test_input.c ${CMAKE_SOURCE_DIR}/src/cli/screen/re_input.c
    ${CMAKE_SOURCE_DIR}/src/cli/screen/re_focus.c ${CMAKE_SOURCE_DIR}/src/cli/screen/re_draw.c)
target_link_libraries(re_test_input PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_input
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_input PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME input COMMAND re_test_input)

# The command layer lives in the executable, so testing it means running it. This is
# the only automated coverage a command gets, and without it a command that silently
# answers "nothing references this" passes every other suite.
add_test(NAME xrefs_data
    COMMAND ${CMAKE_COMMAND}
        -DANTISTREFO=$<TARGET_FILE:antistrefo>
        -DEMITTER=$<TARGET_FILE:re_test_cfg>
        -DWORK=${CMAKE_CURRENT_BINARY_DIR}/re_xrefs_fixture.sys
        -P ${CMAKE_CURRENT_SOURCE_DIR}/run_xrefs_data.cmake)

# The control flow suite is separate because a graph that collapses to one block is
# the kind of regression that every other suite happily passes, so it gets its own
# binary and a hand assembled fixture whose every edge is known in advance.
add_executable(re_test_cfg test_cfg.c)
target_link_libraries(re_test_cfg PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_cfg
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_cfg PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME cfg COMMAND re_test_cfg)

# The stack suite is separate because the argument inference is the one pass whose
# failure is invisible: a wrong argument count still compiles to plausible output.
add_executable(re_test_stack test_stack.c)
target_link_libraries(re_test_stack PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_stack
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_stack PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME stack COMMAND re_test_stack)

# The JSON reader suite is separate because a reader that is lenient about a malformed
# frame is a protocol bug that shows up as a mysterious client disconnect.
add_executable(re_test_jr test_jr.c)
target_link_libraries(re_test_jr PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_jr
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_jr PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME jr COMMAND re_test_jr)

# The PE suite is separate because "is this address code or data" is the question a
# wrong answer to makes every later pass quietly wrong, and the fixture it shares with
# the cfg suite lives in a header so the two cannot disagree about the bytes.
add_executable(re_test_pe test_pe.c ${CMAKE_SOURCE_DIR}/src/cli/screen/re_gui_model.c)
target_link_libraries(re_test_pe PRIVATE re_core re_utils re_flags)
if(MSVC)
    set_property(TARGET re_test_pe
        PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(re_test_pe PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME pe COMMAND re_test_pe)
