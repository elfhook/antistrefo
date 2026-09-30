// re_mcp.h - entry point for the MCP stdio server.
// Module: mcp (C++17).
// Owns: the start of the stdio server loop. Task 4 replaces the body with JSON-RPC.
// Depends: re_utils. main() in src/cli/main.cpp owns the dispatch into this.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
// Protocol revision this build speaks. Reported in the initialize response.
const char *re_mcp_protocol_version(void);

// Serve until stdin reaches EOF, then return 0. Mutes logging before the first
// read, because stdout is the protocol stream from that point on.
int re_mcp_main(void);
#ifdef __cplusplus
}
#endif
