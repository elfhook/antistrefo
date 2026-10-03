// re_term.c - the only file that talks to the console.
// Module: cli (C11).
// Owns: re_term.h. Everything platform specific in the front end lives here.
// Depends: re_term.h, re_input.h, re_tui (size and tty policy).
#include "cli/screen/re_term.h"

#include "utils/tui/re_tui.h"

#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#    include <windows.h>
#    define RE_READ_HANDLE() GetStdHandle(STD_INPUT_HANDLE)
#else
#    include <errno.h>
#    include <poll.h>
#    include <termios.h>
#    include <unistd.h>
#endif

// The sequences. Alt screen 1049 rather than 47 or 1047 because 1049 saves the cursor
// and the scrollback together, so leaving it puts the reader back where they were
// rather than at the top of a screenful of someone else's output.
#define SEQ_ALT_ON "\x1b[?1049h"
#define SEQ_ALT_OFF "\x1b[?1049l"
#define SEQ_CUR_HIDE "\x1b[?25l"
#define SEQ_CUR_SHOW "\x1b[?25h"
#define SEQ_CLEAR "\x1b[2J"
#define SEQ_MOUSE_ON "\x1b[?1000h\x1b[?1002h\x1b[?1006h"
#define SEQ_MOUSE_OFF "\x1b[?1006l\x1b[?1002l\x1b[?1000l"

static void emit(const char *s) {
    if (s)
        fputs(s, stdout);
}

// Put the input side into raw mode, remembering what to put back. False when there is
// nothing to configure or the platform refuses, in which case nothing was changed.
static bool raw_on(re_term_t *t) {
#if defined(_WIN32)
    HANDLE h = RE_READ_HANDLE();
    DWORD mode = 0;
    if (h == INVALID_HANDLE_VALUE || !GetConsoleMode(h, &mode))
        return false;
    t->saved_in = mode;
    DWORD want = mode;
    // Line input and echo have to go, or the terminal collects a whole line before
    // the program sees it. Processed input stays on, so Ctrl-C still interrupts: a
    // front end that ignores Ctrl-C has to be killed from another terminal, which is
    // a much worse thing to tell somebody than a crash.
    want &= ~(DWORD)(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_QUICK_EDIT_MODE);
    want |= ENABLE_VIRTUAL_TERMINAL_INPUT;
    // A console too old for virtual terminal input refuses this. Degrading is
    // correct: the alternative is a session printing escapes nothing will read.
    if (!SetConsoleMode(h, want))
        return false;
    t->have_saved = true;
    return true;
#else
    struct termios orig;
    if (tcgetattr(STDIN_FILENO, &orig) != 0)
        return false;
    struct termios raw = orig;
    // ISIG is kept, for the same reason Ctrl-C is kept on Windows. The rest is the
    // usual raw set: no echo, no line buffering, no CR translation, and zero bytes
    // minimum so the poll in re_term_wait decides how long to wait rather than the
    // tty deciding to block until a line arrives.
    raw.c_lflag &= (tcflag_t) ~(ECHO | ICANON | IEXTEN);
    raw.c_iflag &= (tcflag_t) ~(IXON | ICRNL | BRKINT | INPCK | ISTRIP);
    raw.c_oflag &= (tcflag_t) ~(OPOST);
    raw.c_cflag |= CS8;
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) != 0)
        return false;
    t->have_saved = true;
    return true;
#endif
}

bool re_term_open(re_term_t *t, bool want_mouse) {
    re_input_init(&t->in);
    t->open = false;
    t->mouse = false;
    t->alt_screen = false;
    t->degraded = false;
    t->have_saved = false;
    t->saved_in = 0;
    t->saved_out = 0;
    // Both ends, then raw mode. A failure at any of the three leaves the terminal
    // exactly as it was, because raw_on only sets its flag after it has succeeded.
    if (!re_tui_is_tty() || !re_tui_stdin_tty() || !raw_on(t)) {
        t->degraded = true;
        return false;
    }
    emit(SEQ_ALT_ON);
    emit(SEQ_CUR_HIDE);
    emit(SEQ_CLEAR);
    t->alt_screen = true;
    t->want_mouse = want_mouse;
    if (want_mouse) {
        emit(SEQ_MOUSE_ON);
        t->mouse = true;
    }
    fflush(stdout);
    t->open = true;
    return true;
}

void re_term_finish(re_term_t *t) {
    if (t->mouse) {
        emit(SEQ_MOUSE_OFF);
        t->mouse = false;
    }
    if (t->alt_screen) {
        emit(SEQ_CUR_SHOW);
        emit(SEQ_ALT_OFF);
        t->alt_screen = false;
    }
    fflush(stdout);
}

// Put the input side back the way it was. Called on the way out and from the interrupt
// handler, so it must not fail loudly and must be safe when raw_on never ran.
static void raw_off(re_term_t *t) {
    if (!t->have_saved)
        return;
#if defined(_WIN32)
    HANDLE h = RE_READ_HANDLE();
    if (h != INVALID_HANDLE_VALUE)
        SetConsoleMode(h, t->saved_in);
#else
    struct termios cur;
    if (tcgetattr(STDIN_FILENO, &cur) == 0) {
        cur.c_lflag |= (tcflag_t)(ECHO | ICANON | IEXTEN);
        cur.c_iflag |= (tcflag_t)(IXON | ICRNL);
        cur.c_oflag |= (tcflag_t)OPOST;
        cur.c_cc[VMIN] = 1;
        cur.c_cc[VTIME] = 0;
        tcsetattr(STDIN_FILENO, TCSANOW, &cur);
    }
#endif
    t->have_saved = false;
}

void re_term_close(re_term_t *t) {
    re_term_finish(t);
    raw_off(t);
    t->open = false;
}

void re_term_pause(re_term_t *t) {
    re_term_finish(t);
    raw_off(t);
    t->open = false;
}

bool re_term_resume(re_term_t *t) {
    if (!raw_on(t))
        return false;
    emit(SEQ_ALT_ON);
    emit(SEQ_CUR_HIDE);
    emit(SEQ_CLEAR);
    t->alt_screen = true;
    t->open = true;
    if (t->want_mouse) {
        emit(SEQ_MOUSE_ON);
        t->mouse = true;
    }
    fflush(stdout);
    return true;
}

void re_term_size(uint16_t *rows, uint16_t *cols) {
    re_tui_term_size(rows, cols);
}

bool re_term_has_mouse(const re_term_t *t) {
    return t->mouse;
}

bool re_term_pending(re_term_t *t) {
    if (!t->open)
        return false;
#if defined(_WIN32)
    HANDLE h = RE_READ_HANDLE();
    if (h == INVALID_HANDLE_VALUE)
        return false;
    // A zero timeout ask: the event is drained below whether or not it was ready, so
    // that a mouse move left in the buffer does not sit there until the next wait.
    DWORD ev = 0;
    if (!GetNumberOfConsoleInputEvents(h, &ev) || ev == 0)
        return false;
    return true;
#else
    struct pollfd p;
    p.fd = STDIN_FILENO;
    p.events = POLLIN;
    p.revents = 0;
    return poll(&p, 1, 0) > 0 && (p.revents & POLLIN) != 0;
#endif
}

// Drain whatever bytes are waiting into the decoder. Returns how many were taken, so a
// caller looping until it returns zero terminates on a quiet console.
static size_t drain(re_term_t *t) {
    uint8_t buf[128];
    size_t total = 0;
#if defined(_WIN32)
    HANDLE h = RE_READ_HANDLE();
    if (h == INVALID_HANDLE_VALUE)
        return 0;
    DWORD avail = 0;
    while (GetNumberOfConsoleInputEvents(h, &avail) && avail > 0) {
        INPUT_RECORD rec;
        DWORD got = 0;
        if (!ReadConsoleInputA(h, &rec, 1, &got) || got == 0)
            break;
        if (rec.EventType != KEY_EVENT || !rec.Event.KeyEvent.bKeyDown)
            continue;
        char ch = rec.Event.KeyEvent.uChar.AsciiChar;
        if (!ch)
            continue; // a key with no ASCII byte: a dead key, or a compose in progress
        buf[total % sizeof(buf)] = (uint8_t)ch;
        total++;
        if (total >= sizeof(buf))
            break;
    }
#else
    for (;;) {
        ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
        if (n > 0) {
            total = (size_t)n;
            break;
        }
        if (n < 0 && errno != EAGAIN && errno != EINTR)
            break;
        if (n == 0)
            break;
        break;
    }
#endif
    if (total)
        re_input_feed(&t->in, buf, total);
    return total;
}

bool re_term_wait(re_term_t *t, re_ev_t *out, unsigned timeout_ms) {
    if (!t->open)
        return false;
    for (;;) {
        if (re_input_next(&t->in, out))
            return true;
#if defined(_WIN32)
        // A resize arrives as a console event rather than as bytes, so the window
        // record is drained here instead of waiting for a key that will never come.
        HANDLE h = RE_READ_HANDLE();
        DWORD ev = 0;
        while (h != INVALID_HANDLE_VALUE && GetNumberOfConsoleInputEvents(h, &ev) && ev > 0) {
            INPUT_RECORD rec;
            DWORD got = 0;
            if (!ReadConsoleInputA(h, &rec, 1, &got) || got == 0)
                break;
            if (rec.EventType == WINDOW_BUFFER_SIZE_EVENT) {
                drain(t);
                while (re_input_next(&t->in, out)) {
                }
                out->kind = RE_EV_RESIZE;
                out->key = RE_KEY_RESIZE;
                return true;
            }
            if (rec.EventType == KEY_EVENT && rec.Event.KeyEvent.bKeyDown) {
                char ch = rec.Event.KeyEvent.uChar.AsciiChar;
                if (ch) {
                    re_input_feed(&t->in, (const uint8_t *)&ch, 1);
                }
            }
        }
        if (timeout_ms == 0)
            return false;
        WaitForSingleObject(h, timeout_ms);
#else
        struct pollfd p;
        p.fd = STDIN_FILENO;
        p.events = POLLIN;
        p.revents = 0;
        int pr = poll(&p, 1, (int)timeout_ms);
        if (pr <= 0)
            return false; // a timeout, or a signal: the caller redraws either way
        if (drain(t) == 0 && timeout_ms)
            continue; // a wakeup with no bytes yet; try once more within the budget
#endif
        if (re_input_next(&t->in, out))
            return true;
        if (timeout_ms == 0)
            return false;
    }
}

void re_term_write(re_term_t *t, const char *bytes, size_t n) {
    if (!t || !bytes || !n)
        return;
    fwrite(bytes, 1, n, stdout);
    fflush(stdout);
}
