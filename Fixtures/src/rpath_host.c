/* Host with two LC_RPATH entries pointing at directories that both
   contain libcollide.dylib. Used only inside Fixtures/. */
void collide_marker(void);

int main(void) {
    collide_marker();
    return 0;
}
