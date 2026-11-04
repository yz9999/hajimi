#include "Runtime.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <new>
#include <stdexcept>

namespace {
std::atomic<bool> countAllocations{false};
std::atomic<size_t> allocations{0};
}

__attribute__((noinline)) void *operator new(std::size_t size) {
    if (countAllocations.load(std::memory_order_relaxed))
        allocations.fetch_add(1, std::memory_order_relaxed);
    if (void *value = std::malloc(size ? size : 1)) return value;
    throw std::bad_alloc();
}
__attribute__((noinline)) void *operator new[](std::size_t size) { return ::operator new(size); }
__attribute__((noinline)) void operator delete(void *value) noexcept { std::free(value); }
__attribute__((noinline)) void operator delete[](void *value) noexcept { std::free(value); }
__attribute__((noinline)) void operator delete(void *value, std::size_t) noexcept { ::operator delete(value); }
__attribute__((noinline)) void operator delete[](void *value, std::size_t) noexcept { ::operator delete[](value); }

namespace {
class FreshChunkStream final : public hajimi::Stream {
public:
    explicit FreshChunkStream(size_t chunk) : chunk_(chunk) {}
    void read(size_t maximum, hajimi::ReadCallback completion) override {
        const auto count = std::min(maximum, chunk_);
        const auto value = static_cast<uint8_t>(++sequence_ % 251);
        completion(hajimi::Buffer(count, value), false, {});
    }
    void write(hajimi::Buffer, hajimi::WriteCallback completion) override { completion({}); }
    void close() override {}
private:
    size_t chunk_, sequence_ = 0;
};

void run(size_t chunk, size_t iterations) {
    auto source = std::make_shared<FreshChunkStream>(chunk);
    auto reader = std::make_shared<hajimi::Reader>(source);
    size_t delivered = 0, callbacks = 0;
    uint64_t checksum = 0;
    auto receive = [&](hajimi::Buffer data, bool eof, hajimi::Error error) {
        if (eof || !error.empty() || data.size() != chunk)
            throw std::runtime_error("Reader performance fixture changed stream semantics");
        delivered += data.size(); ++callbacks;
        checksum += data.front() + data.back();
    };
    for (size_t index = 0; index < 32; ++index) reader->some(chunk, receive);
    delivered = callbacks = checksum = 0;
    allocations.store(0); countAllocations.store(true);
    const auto started = std::chrono::steady_clock::now();
    for (size_t index = 0; index < iterations; ++index) reader->some(chunk, receive);
    const auto stopped = std::chrono::steady_clock::now();
    countAllocations.store(false);
    if (callbacks != iterations || delivered != iterations * chunk || !checksum)
        throw std::runtime_error("Reader performance fixture lost bytes/callbacks");
    const double elapsed = std::chrono::duration<double>(stopped - started).count();
    std::cout << "Reader copy/allocation fixture: " << chunk << "-byte chunks, "
              << iterations << " reads, " << allocations.load() << " allocations, "
              << std::fixed << std::setprecision(2) << elapsed * 1000 << " ms, "
              << double(delivered) / 1048576.0 / elapsed << " MiB/s, checksum="
              << checksum << " (memory-only; not proxy or Internet throughput)\n";
    reader->close();
}
}

int main() {
    try {
        run(1024, 100000);
        run(32768, 20000);
        run(65536, 10000);
        return 0;
    } catch (const std::exception &error) {
        countAllocations.store(false);
        std::cerr << "Reader performance fixture failed: " << error.what() << '\n';
        return 1;
    }
}
