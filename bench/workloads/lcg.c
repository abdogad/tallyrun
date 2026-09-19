/* LCG dependency chain in registers: the well-behaved compiled baseline.
 * The hot loop never touches memory, so it takes ~4 cycles per iteration on
 * Zen 2 (imul 3 + add 1) and its CPU time is as stable as compiled code
 * gets. Compare spin.c, whose volatile store-load chain has two speeds, up
 * to 8x apart, on the same tuned machine. */
#include <stdio.h>

int main(void) {
    unsigned long long s = 88172645463325252ULL;
    for (long i = 0; i < 800000000L; i++)
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
    printf("%llu\n", s);
    return 0;
}
