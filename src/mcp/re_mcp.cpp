// re_mcp.cpp - MCP stdio server, C++17 shell over the C11 core.
// Module: mcp (C++17).
// Owns: stdio framing and the serve loop. Task 4 adds JSON-RPC dispatch inside it.
// Depends: re_mcp.h and re_utils. Writes nothing to stdout except protocol frames.
#include "mcp/re_mcp.h"

#include "utils/re_util.h"

namespace {

// MCP stdio uses newline delimited JSON-RPC, not the Content-Length framing that
// LSP style transports use. Getting this wrong silently corrupts the stream.
constexpr const char *kProtocolVersion = "2025-06-18";

} // namespace

const char *re_mcp_protocol_version(void) {
    return kProtocolVersion;
}

int re_mcp_main(void) {
    // Mute logging outright. stdout carries protocol frames, so a stray write
    // there looks like a protocol violation to the client.
    re_log_set_mute(true);
    char line[4096];
    while (fgets(line, sizeof(line), stdin)) {
        RE_LOGI("mcp frame of %zu bytes received, dispatch lands in task 4", re_str(line).n);
    }
    return 0;
}
