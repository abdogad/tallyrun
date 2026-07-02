/* Memory-bound worst case: 64 MiB working set walked with a fixed-seed LCG,
 * so nearly every access misses cache and the first pass page-faults ~16k
 * times. This is the workload where "page faults perturb the count" should
 * show up if it's going to. */
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
