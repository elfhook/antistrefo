# run_flirt_names.cmake - the naming chain, through the command a reader would run.
# Module: test (CMake).
# Owns: writing signature files, running funcs over them, and checking what came back.
# Depends: the antistrefo executable and the fixture emitter. A name reaching the
#       report is the only proof that loading, compiling, indexing and naming are all
#       wired together; each half can pass its own unit test while the chain is broken.
execute_process(COMMAND "${EMITTER}" --emit "${WORK}" RESULT_VARIABLE wrote)
if(NOT wrote EQUAL 0)
    message(FATAL_ERROR "could not write the fixture: ${wrote}")
endif()

# The fixture's third function opens with 53 48 83 ec (push rbx; sub rsp, 0x20) and no
# export names it, so this is the case where a signature is the only name there is.
# The pattern is written here rather than read from the built in set, so this test
# still fails if that set is emptied, which is the failure it exists to catch.
file(WRITE "${SIGS}" "probe_frame : test : 534883ec\n")
execute_process(
    COMMAND "${ANTISTREFO}" funcs "${WORK}" "${SIGS}"
    OUTPUT_VARIABLE out RESULT_VARIABLE rc)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "funcs failed with ${rc}: ${out}")
endif()
if(NOT out MATCHES "probe_frame")
    message(FATAL_ERROR "a signature from the file did not reach the report: ${out}")
endif()
if(NOT out MATCHES "\"named\":1")
    message(FATAL_ERROR "the named count does not match the one name it applied: ${out}")
endif()
if(NOT out MATCHES "\"signature_file\":\"")
    message(FATAL_ERROR "the report did not say which file it loaded: ${out}")
endif()
if(NOT out MATCHES "\"signatures_loaded\":1")
    message(FATAL_ERROR "the loaded count is wrong: ${out}")
endif()

# An export name is stated by the image and a pattern only infers one, so a signature
# that matches an exported function must not rename it. The fixture's first function
# opens with 48 83 f8 01 and is exported as AlphaFunc.
file(WRITE "${SIGS}" "probe_cmp : test : 4883f8\n")
execute_process(
    COMMAND "${ANTISTREFO}" funcs "${WORK}" "${SIGS}"
    OUTPUT_VARIABLE out2 RESULT_VARIABLE rc2)
if(NOT rc2 EQUAL 0)
    message(FATAL_ERROR "funcs failed with ${rc2}: ${out2}")
endif()
if(NOT out2 MATCHES "AlphaFunc")
    message(FATAL_ERROR "an export name was replaced by a signature: ${out2}")
endif()
if(NOT out2 MATCHES "\"named\":0")
    message(FATAL_ERROR "a signature was counted as naming an already named function: ${out2}")
endif()

# A file whose entries cannot compile must say so. Reporting a database size and
# leaving the reader to assume the patterns are usable is how a file that does nothing
# looks loaded.
file(WRITE "${SIGS}" "good : test : 534883ec\nbad : test : zzzz\nodd : test : 488\n")
execute_process(
    COMMAND "${ANTISTREFO}" funcs "${WORK}" "${SIGS}"
    OUTPUT_VARIABLE out3 RESULT_VARIABLE rc3)
if(NOT rc3 EQUAL 0)
    message(FATAL_ERROR "funcs failed with ${rc3}: ${out3}")
endif()
if(NOT out3 MATCHES "\"signatures_rejected\":2")
    message(FATAL_ERROR "refused entries were not reported: ${out3}")
endif()
if(NOT out3 MATCHES "\"signatures_loaded\":1")
    message(FATAL_ERROR "the loaded count is wrong: ${out3}")
endif()
message(STATUS "signatures load, name, defer to exports and are accounted for")
file(REMOVE "${WORK}")
file(REMOVE "${SIGS}")
