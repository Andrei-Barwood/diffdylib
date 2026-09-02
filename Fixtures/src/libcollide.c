/* Laboratory fixture: same basename planted in two rpath directories. */
#include <stdio.h>

void collide_marker(void) {
    fputs("fixture loaded: libcollide\n", stderr);
}
