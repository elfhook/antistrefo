# run_walk_quality.cmake - the recovery cases, through the command a reader runs.
# Module: test (CMake).
# Owns: writing the recovery fixture, running funcs over it, and checking the report.
# Depends: the antistrefo executable and the fixture emitter. Each of these cases is a
#       field that only appears when the walk met the condition: bytes it could not
#       decode, a branch into bytes another function claimed, a body past the
#       instruction ceiling, and a tail that cannot return. A unit test can construct
#       the walk directly, but then it is not proving the field reaches the report.
execute_process(COMMAND "${EMITTER}" --emit-walk "${WORK}" RESULT_VARIABLE wrote)
if(NOT wrote EQUAL 0)
    message(FATAL_ERROR "could not write the recovery fixture: ${wrote}")
endif()

execute_process(
    COMMAND "${ANTISTREFO}" funcs "${WORK}" --limit 1000
    OUTPUT_VARIABLE out RESULT_VARIABLE rc)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "funcs failed with ${rc}: ${out}")
endif()

# AlphaFunc holds three bytes that decode to nothing. The field carries the count,
# because a reader needs to know how much of the body was skipped, and the flag says
# the body was not contiguous.
if(NOT out MATCHES "\"junk\":3")
    message(FATAL_ERROR "the skipped byte count is wrong: ${out}")
endif()
if(NOT out MATCHES "AlphaFunc")
    message(FATAL_ERROR "the export name did not reach the report: ${out}")
endif()

# GammaFunc branches into the middle of the entry point's first instruction, which is
# an overlap: two bodies sharing bytes.
if(NOT out MATCHES "\"overlap\"")
    message(FATAL_ERROR "a branch into claimed bytes was not reported: ${out}")
endif()

# DeltaFunc is longer than the instruction ceiling, so the walk stops and says so
# rather than reporting a body that looks complete.
if(NOT out MATCHES "\"truncated\":true")
    message(FATAL_ERROR "a body past the ceiling was reported as complete: ${out}")
endif()
if(NOT out MATCHES "\"trunc\"")
    message(FATAL_ERROR "the truncation flag is missing: ${out}")
endif()
if(NOT out MATCHES "\"insns\":4096")
    message(FATAL_ERROR "the walk did not reach the ceiling: ${out}")
endif()

# EpsilonFunc ends in ud2 and never returns. It is the case a caller needs to know
# about before assuming a function falls through to something.
if(NOT out MATCHES "\"noreturn\"")
    message(FATAL_ERROR "a halting tail was not reported: ${out}")
endif()

# The sixth function is named by nothing at all: no export, no unwind entry, no
# prologue, and no transfer points at it. The only thing in the image that mentions it
# is a code pointer in .rdata, so finding it at all proves the seed scan ran and that
# the walk accepts a start it was handed rather than one it derived.
if(NOT out MATCHES "\"total\":6")
    message(FATAL_ERROR "the code pointer seed did not produce a function: ${out}")
endif()

message(STATUS "junk, overlap, truncation, noreturn and the pointer seed all reach the report")
file(REMOVE "${WORK}")
