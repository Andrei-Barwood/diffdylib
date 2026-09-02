/* Laboratory host that stays alive so tests can inspect its pid.
   Links libmid. Not a real application. */
#include <unistd.h>

void mid_hello(void);

int main(void) {
    mid_hello();
    pause();
    return 0;
}
