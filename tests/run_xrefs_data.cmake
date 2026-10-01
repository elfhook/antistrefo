# run_xrefs_data.cmake - the command layer test, which needs a real file to run against.
# Module: test (CMake).
# Owns: writing the fixture, then checking that xrefs answers for a data address.
# Depends: the antistrefo executable and the fixture emitter. The command code is in
#       the executable, not in a library, so this is the only place a command's
#       behaviour can be asserted automatically.
execute_process(COMMAND "${EMITTER}" --emit "${WORK}" RESULT_VARIABLE wrote)
if(NOT wrote EQUAL 0)
    message(FATAL_ERROR "could not write the fixture: ${wrote}")
endif()

# The address of the fixture's first export name, "AlphaFunc", which lives in .edata
# and is therefore not inside any function. Asking about it used to report zero
# references because the query window was left at zero for a subject that is not in a
# function, so every string looked like nothing pointed at it.
set(addr "0x1450205c")
execute_process(
    COMMAND "${ANTISTREFO}" xrefs "${WORK}" "${addr}"
    OUTPUT_VARIABLE out RESULT_VARIABLE rc)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "xrefs failed with ${rc}: ${out}")
endif()
if(NOT out MATCHES "\"subject_data\":true")
    message(FATAL_ERROR "a data subject was not reported as one: ${out}")
endif()
if(NOT out MATCHES "\"subject_span\":1")
    message(FATAL_ERROR "a data subject got no window: ${out}")
endif()
message(STATUS "xrefs answers for a data address")
file(REMOVE "${WORK}")
