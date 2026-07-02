/* volatile store-load loop — every iteration stores and reloads the
 * accumulator's stack slot, making runtime hostage to the store-forwarding
 * pipeline. Empirically time-BIMODAL (up to 8x between process instances) on
 * Zen 2 even with pinned clocks, cool package, idle machine, and ASLR off —
 * while the instruction count stays identical to ~7 digits. Kept as the
 * exhibit that CPU time can be microarchitecturally capricious; lcg.c is the
 * well-behaved compiled baseline. */
#include <stdio.h>

int main(void) {
    volatile unsigned long long s = 0;
    for (unsigned long long i = 0; i < 800000000ULL; i++)
        s += i;
    printf("%llu\n", s);
    return 0;
}
