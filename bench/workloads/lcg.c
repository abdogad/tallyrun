/* Register-only dependency chain (LCG): the well-behaved compiled baseline.
 * No memory traffic in the hot loop, so ~4 cycles/iteration on Zen 2 (imul 3
 * + add 1) — CPU time is as stable as compiled time gets. Contrast with
 * spin.c, whose volatile store-load chain is time-bimodal (up to 8x) on the
 * same tuned machine. */
#include <stdio.h>

int main(void) {
    unsigned long long s = 88172645463325252ULL;
    for (long i = 0; i < 800000000L; i++)
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
    printf("%llu\n", s);
    return 0;
}
