// re_pseudocode.h - the pure part of showing a decompiled body.
// Module: cli (C11).
// Owns: marking the lines worth marking, and splitting a body into lines.
// Depends: nothing. Header only, because both are a few lines of text handling and
//           putting them behind a .c would make them untestable: the file they came
//           from needs a terminal and an analysed file, and neither can be here.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// How many lines of pseudocode a pane will ever show. The bound is a pane's worth, not
// a promise about the body: a longer one is cut and the caller is expected to say so.
#define RE_PSEUDO_MAX 96u

// Does the line carry this word? Compared a byte at a time and bounded by the line
// ending, rather than handed to a libc call: the rules keep libc string calls out of
// this layer, and a bounded scan is the same answer without the dependency.
static inline bool re_pseudo_has(const char *line, const char *word) {
    for (size_t i = 0; line[i] && line[i] != '\n'; i++) {
        size_t k = 0;
        while (word[k] && line[i + k] == word[k])
            k++;
        if (!word[k])
            return true;
    }
    return false;
}

// The lines worth marking in a pseudocode pane: the control flow skeleton. A label, a
// branch, a call or a return is where a reader's eye stops, and the emitter's output
// shape is what identifies them. Marking every statement would mark every line, which
// says nothing, and the arithmetic between the landmarks is what it is.
//
// The forms recognised are the ones the emitter writes: a label as a name, a colon and
// the line ending; a branch as a goto; a call as an assignment whose right side is a
// call; a return as the keyword. An instruction the emitter could not lower is left
// unmarked, because it is already a comment and does not need the column as well.
static inline uint8_t re_pseudo_mark(const char *line) {
    if (line[0] == 'L') {
        size_t n = 1;
        while (line[n] && line[n] != ':')
            n++;
        // Anything longer after the colon is an expression that happens to begin
        // with an L, not a label.
        if (n > 1 && line[n] == ':' && (line[n + 1] == '\n' || line[n + 1] == '\0'))
            return 1;
    }
    if (re_pseudo_has(line, "goto") || re_pseudo_has(line, "return"))
        return 1;
    if (re_pseudo_has(line, "=") && re_pseudo_has(line, "("))
        return 1;
    return 0;
}

// Split a body into line pointers, marking each, and terminate every line in place.
//
// The text is edited rather than copied: each line ending becomes a terminator, so the
// pointers are C strings and the grid never sees a newline byte inside a cell, which it
// would otherwise draw as a control character and corrupt the row. The caller owns the
// buffer and rewrites it before asking again, so nothing is lost.
//
// Returns how many lines were taken, which is fewer than the body has when the bound is
// reached. That is the cut, and the count is what reports it.
static inline size_t re_pseudo_split(char *text, const char **lines, uint8_t *marks, size_t cap) {
    size_t n = 0;
    if (!text)
        return 0;
    while (*text && n < cap) {
        lines[n] = text;
        marks[n] = re_pseudo_mark(text);
        n++;
        while (*text && *text != '\n')
            text++;
        if (*text == '\n')
            *text++ = '\0';
        else
            break; // the last line had no ending; nothing more to take
    }
    return n;
}

#ifdef __cplusplus
}
#endif
