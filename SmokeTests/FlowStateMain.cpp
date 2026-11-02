#include "HajimiFlowCXX.h"
#include <cstdio>
int main() {
    const int result = hajimi_flow_self_test();
    if (result) { std::fprintf(stderr, "C++ flow self-test failed: %d\n", result); return 1; }
    std::puts("C++ bounded queue / TCP reassembly / RTO self-test passed");
    return 0;
}
