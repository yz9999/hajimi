// The runner inserts the actual private post helper from the bridge here.
// No protocol clients, sockets, DNS or system configuration are used.
#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <sys/resource.h>
#include <vector>

namespace {
std::atomic<bool> counting{false};
std::atomic<size_t> countedSize{0}, payloadAllocations{0}, payloadBytes{0};
}
void *operator new(std::size_t size) {
    if (counting.load(std::memory_order_relaxed) && size == countedSize.load(std::memory_order_relaxed)) {
        payloadAllocations.fetch_add(1, std::memory_order_relaxed);
        payloadBytes.fetch_add(size, std::memory_order_relaxed);
    }
    if (void *value = std::malloc(size ? size : 1)) return value;
    throw std::bad_alloc();
}
void *operator new[](std::size_t size) { return ::operator new(size); }
void operator delete(void *value) noexcept { std::free(value); }
void operator delete[](void *value) noexcept { std::free(value); }

namespace {
// HAJIMI_PRODUCTION_POST_HELPER

unsigned checks = 0;
void expect(bool condition, const char *message) {
    ++checks;
    if (!condition) throw std::runtime_error(message);
}
void wait(dispatch_semaphore_t signal, const char *message) {
    expect(dispatch_semaphore_wait(signal, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) == 0, message);
}
struct Gate {
    dispatch_queue_t queue;
    dispatch_semaphore_t release = dispatch_semaphore_create(0);
    bool released = false;
    explicit Gate(dispatch_queue_t value) : queue(value) {
        auto entered = dispatch_semaphore_create(0), resume = release;
        dispatch_async(queue, ^{
            dispatch_semaphore_signal(entered);
            dispatch_semaphore_wait(resume, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC));
        });
        wait(entered, "Queue ownership gate did not start");
    }
    void resume() { if (!released) { released = true; dispatch_semaphore_signal(release); } }
    ~Gate() { resume(); }
};
struct State {
    std::atomic<unsigned> callbacks{0}, destroyed{0};
    std::atomic<bool> valid{true}, cancelled{false};
    std::vector<unsigned> events;
};
struct Lifetime {
    std::shared_ptr<State> state;
    ~Lifetime() { ++state->destroyed; }
};
void payloadOwnership(bool requireSingleOwner) {
    auto queue = dispatch_queue_create("memory.post.ownership", DISPATCH_QUEUE_SERIAL);
    auto done = dispatch_semaphore_create(0);
    auto state = std::make_shared<State>();
    std::weak_ptr<Lifetime> pending;
    Gate gate(queue);
    std::vector<uint8_t> payload(65537);
    for (size_t index = 0; index < payload.size(); ++index) payload[index] = uint8_t(index * 131 + 17);
    const auto *original = payload.data();
    auto sameStorage = std::make_shared<std::atomic<bool>>(false);
    {
        auto owner = std::make_shared<Lifetime>(); owner->state = state; pending = owner;
        std::function<void()> work = [payload = std::move(payload), original, sameStorage, state, owner, done] {
            *sameStorage = payload.data() == original;
            for (size_t index = 0; index < payload.size(); ++index)
                if (payload[index] != uint8_t(index * 131 + 17)) state->valid = false;
            ++state->callbacks; dispatch_semaphore_signal(done);
        };
        countedSize = 65537; payloadAllocations = 0; payloadBytes = 0; counting = true;
        post(queue, std::move(work));
        counting = false;
    }
    const auto copies = payloadAllocations.load(), bytes = payloadBytes.load();
    expect(!pending.expired() && state->callbacks == 0 && state->destroyed == 0,
           "Queued work ran synchronously or lost its capture owner");
    gate.resume(); wait(done, "Posted payload callback missing"); dispatch_sync(queue, ^{});
    expect(state->valid && state->callbacks == 1, "Posted payload changed bytes or repeated its callback");
    expect(pending.expired() && state->destroyed == 1, "Completed work retained or prematurely destroyed its captures");
    if (requireSingleOwner) expect(copies == 0 && bytes == 0 && *sameStorage,
                                   "Posting copied the captured payload instead of transferring ownership");
    std::printf("Captured 65537-byte vector: %zu payload allocations, %zu copied bytes; storage transferred=%s\n",
                copies, bytes, *sameStorage ? "yes" : "no");
}
void orderingAndTrampoline() {
    auto queue = dispatch_queue_create("memory.post.order", DISPATCH_QUEUE_SERIAL);
    auto done = dispatch_semaphore_create(0), nested = dispatch_semaphore_create(0);
    auto state = std::make_shared<State>();
    Gate gate(queue);
    for (unsigned index = 0; index < 64; ++index) post(queue, [state, index, done] {
        state->events.push_back(index); ++state->callbacks;
        if (index == 63) dispatch_semaphore_signal(done);
    });
    expect(state->callbacks == 0, "Pending work escaped its serial queue");
    gate.resume(); wait(done, "FIFO tasks did not complete"); dispatch_sync(queue, ^{});
    expect(state->callbacks == 64 && state->events.size() == 64, "FIFO tasks were lost or duplicated");
    for (unsigned index = 0; index < 64; ++index) expect(state->events[index] == index, "FIFO order changed");
    state->events.clear();
    post(queue, [queue, state, nested] {
        state->events.push_back(1);
        post(queue, [state, nested] { state->events.push_back(3); dispatch_semaphore_signal(nested); });
        state->events.push_back(2);
    });
    wait(nested, "Nested task was lost"); dispatch_sync(queue, ^{});
    expect(state->events == std::vector<unsigned>({1, 2, 3}), "Nested posting recursed synchronously");
}
void canceledCaptures() {
    auto queue = dispatch_queue_create("memory.post.cancel", DISPATCH_QUEUE_SERIAL);
    auto done = dispatch_semaphore_create(0);
    auto state = std::make_shared<State>(); std::weak_ptr<Lifetime> pending;
    Gate gate(queue);
    {
        auto owner = std::make_shared<Lifetime>(); owner->state = state; pending = owner;
        post(queue, [owner, state, done] {
            if (!state->cancelled) state->valid = false;
            ++state->callbacks; dispatch_semaphore_signal(done);
        });
    }
    state->cancelled = true;
    expect(!pending.expired(), "Cancel state destroyed queued captures before queue delivery");
    gate.resume(); wait(done, "Cancel-state cleanup callback missing"); dispatch_sync(queue, ^{});
    expect(state->valid && state->callbacks == 1 && state->destroyed == 1 && pending.expired(),
           "Cancel-state task changed delivery count, visibility or ownership cleanup");
}
double cpuSeconds() {
    rusage value{};
    if (getrusage(RUSAGE_SELF, &value)) throw std::runtime_error("Cannot read process CPU time");
    return double(value.ru_utime.tv_sec + value.ru_stime.tv_sec)
        + double(value.ru_utime.tv_usec + value.ru_stime.tv_usec) / 1e6;
}
void benchmark(size_t chunk, size_t iterations) {
    auto queue = dispatch_queue_create("memory.post.benchmark", DISPATCH_QUEUE_SERIAL);
    auto done = dispatch_semaphore_create(0);
    auto completed = std::make_shared<std::atomic<size_t>>(0);
    auto valid = std::make_shared<std::atomic<bool>>(true);
    size_t copies = 0, bytes = 0;
    double wall = 0, cpu = 0;
    constexpr size_t batchSize = 64;
    for (size_t first = 0; first < iterations; first += batchSize) {
        const size_t count = std::min(batchSize, iterations - first);
        std::vector<std::function<void()>> tasks; tasks.reserve(count);
        for (size_t index = 0; index < count; ++index) {
            const uint8_t salt = uint8_t((first + index) % 251);
            std::vector<uint8_t> payload(chunk, salt);
            tasks.emplace_back([payload = std::move(payload), completed, valid, done, salt, index, count] {
                if (payload.front() != salt || payload[payload.size() / 2] != salt || payload.back() != salt) *valid = false;
                ++*completed;
                if (index + 1 == count) dispatch_semaphore_signal(done);
            });
        }
        countedSize = chunk; payloadAllocations = 0; payloadBytes = 0; counting = true;
        const double startedCPU = cpuSeconds(); const auto started = std::chrono::steady_clock::now();
        for (auto &work : tasks) post(queue, std::move(work));
        wait(done, "Benchmark batch did not complete"); dispatch_sync(queue, ^{});
        wall += std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
        cpu += cpuSeconds() - startedCPU;
        counting = false; copies += payloadAllocations.load(); bytes += payloadBytes.load();
    }
    expect(*completed == iterations && *valid, "Benchmark changed payload/callback semantics");
    std::printf("Post scheduling: chunk=%zu iterations=%zu payload_allocations=%zu copied_bytes=%zu wall_ms=%.3f cpu_ms=%.3f (memory-only)\n",
                chunk, iterations, copies, bytes, wall * 1000, cpu * 1000);
}
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        try {
            bool singleOwner = false, measure = false;
            for (int index = 1; index < argc; ++index) {
                if (std::string(argv[index]) == "--require-single-owner") singleOwner = true;
                else if (std::string(argv[index]) == "--benchmark") measure = true;
                else throw std::runtime_error("Unknown post fixture argument");
            }
            payloadOwnership(singleOwner); orderingAndTrampoline(); canceledCaptures();
            if (measure) { benchmark(1024, 32768); benchmark(32768, 8192); benchmark(65536, 4096); }
            std::printf("Native C++ post dispatch: %u checks passed (memory-only)\n", checks);
            return 0;
        } catch (const std::exception &error) {
            counting = false; std::fprintf(stderr, "Native C++ post dispatch failed: %s\n", error.what()); return 1;
        }
    }
}
