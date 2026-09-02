/* Laboratory fixture. Constructor only logs; no network, no persistence. */
#include <stdio.h>

void leaf_hello(void) {
    fputs("fixture loaded: libleaf\n", stderr);
}

__attribute__((constructor))
static void leaf_ctor(void) {
    fputs("fixture loaded: libleaf ctor\n", stderr);
}
