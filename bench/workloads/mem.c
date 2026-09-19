/* Memory-bound worst case: a fixed-seed LCG walks a 64 MiB array, so nearly
 * every access misses cache and the first pass takes ~16k page faults. If
 * page faults disturbed the instruction count, it would show here. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(void) {
    const size_t n = 16u * 1024 * 1024; /* 2^24 uint32 = 64 MiB */
    uint32_t *a = malloc(n * sizeof *a);
    if (!a)
        return 1;
    for (size_t i = 0; i < n; i++)
        a[i] = (uint32_t)i;
    uint32_t x = 123456789u;
    uint64_t s = 0;
    for (size_t i = 0; i < 8u * 1024 * 1024; i++) {
        x = x * 1664525u + 1013904223u;
        s += a[x & (n - 1)];
    }
    printf("%llu\n", (unsigned long long)s);
    free(a);
    return 0;
}
