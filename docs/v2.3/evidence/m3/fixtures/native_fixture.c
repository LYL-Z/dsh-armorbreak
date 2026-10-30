volatile int fixture_state = 3;
__attribute__((noinline)) int helper(int a, int b) { return a + b + fixture_state; }
__attribute__((noinline)) int caller(int value) { return helper(value, 3); }
int main(void) { return caller(7); }
