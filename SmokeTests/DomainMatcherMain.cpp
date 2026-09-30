#include "HajimiRoutingCXX.h"

#include <cstdio>

int main() {
    const int32_t failure = hajimi_domain_match_self_test();
    if (failure != 0) {
        std::fprintf(stderr, "Hajimi native domain self-test vector %d failed\n", failure);
        return 1;
    }
    std::puts("Hajimi native ASCII domain matcher self-test passed");
    return 0;
}
