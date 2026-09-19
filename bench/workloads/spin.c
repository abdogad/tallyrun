/* Volatile store-load loop: every iteration stores the accumulator to its
 * stack slot and loads it back, so speed depends on store forwarding. On
 * Zen 2 the run time is bimodal, up to 8x apart between process instances,
 * even with fixed clocks, a cool package, an idle machine and ASLR off. The
 * instruction count matches to ~7 digits. It stays in the suite to show how
 * erratic CPU time can be; lcg.c is the well-behaved baseline. */
#include <stdio.h>

int main(void) {
    volatile unsigned long long s = 0;
    for (unsigned long long i = 0; i < 800000000ULL; i++)
        s += i;
    printf("%llu\n", s);
    return 0;
}
