/* Laboratory fixture. Forwards to libleaf so depth=2 has something to walk. */
#include <stdio.h>

void leaf_hello(void);

void mid_hello(void) {
    fputs("fixture loaded: libmid\n", stderr);
    leaf_hello();
}

__attribute__((constructor))
static void mid_ctor(void) {
    fputs("fixture loaded: libmid ctor\n", stderr);
}
