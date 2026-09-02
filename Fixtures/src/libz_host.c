/* Host that links only libz so skip-system can be tested. */
#include <zlib.h>
#include <stdio.h>

int main(void) {
    printf("zlib %s\n", zlibVersion());
    return 0;
}
