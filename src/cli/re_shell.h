// re_shell.h - the interactive mode entered when the tool is run with no arguments.
// Module: cli (C11).
// Owns: the prompt loop, and remembering the file being looked at.
// Depends: re_table, re_report, re_tui, re_cmds. Dispatches through the same command
//           table the argv path uses, so the shell is not a second implementation.
//
// The rule that shapes this: with no arguments and a terminal on both ends, stay put
// and read commands. That is what makes double clicking the binary useful. With no
// arguments and a pipe, print usage and exit, because something automated is asking
// and it must not be made to wait for a keystroke that will never come.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include "cli/re_table.h"

// True when the shell should run: no arguments, and stdin and stdout are both
// terminals. A caller that passes arguments never gets here.
bool re_shell_wanted(int argc);

// Run the loop. Returns 0 on a clean exit, which is the only way it returns: an error
// inside a command is reported and the loop continues, because losing a whole session
// to one bad argument is not a useful behaviour for a thing you are exploring with.
int re_shell_run(re_ctx_t *ctx);
#ifdef __cplusplus
}
#endif
