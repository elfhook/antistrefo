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
