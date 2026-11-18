#include "AES.h"
#include <cstddef>
#include <cstdlib>
#include <new>
#include <cstdio>
#ifdef _MSC_VER
#include <crtdbg.h>
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#endif

namespace {
struct alignas(std::max_align_t) AllocationHeader { size_t size; };
bool watching = false;
long failAfter = -1;
unsigned int uncleared = 0;
void inspect(const void* memory, size_t size) {
    if (!watching) return;
    const uint8_t* bytes = static_cast<const uint8_t*>(memory);
    size_t run = 0;
    for (size_t i = 0; i < size; ++i) {
        run = bytes[i] == 0xA5 ? run + 1 : 0;
        if (run >= 16) { ++uncleared; break; }
    }
}
}

void* operator new(size_t size) {
    bool injectable = true;
#if defined(_MSC_VER) && _ITERATOR_DEBUG_LEVEL != 0
    // MSVC allocates iterator proxies inside noexcept vector constructors/moves.
    // Inject failures into recoverable data allocations, not these STL internals.
    injectable = size != sizeof(std::_Container_proxy);
#endif
    if (watching && injectable && failAfter >= 0 && failAfter-- == 0) throw std::bad_alloc();
    if (size > static_cast<size_t>(-1) - sizeof(AllocationHeader)) throw std::bad_alloc();
    auto header = static_cast<AllocationHeader*>(std::malloc(sizeof(AllocationHeader) + size));
    if (!header) throw std::bad_alloc();
    header->size = size;
    return header + 1;
}
void operator delete(void* memory) noexcept {
    if (!memory) return;
    auto header = static_cast<AllocationHeader*>(memory) - 1;
    inspect(memory, header->size);
    std::free(header);
}
void* operator new[](size_t size) { return ::operator new(size); }
void operator delete[](void* memory) noexcept { ::operator delete(memory); }
void operator delete(void* memory, size_t) noexcept { ::operator delete(memory); }
void operator delete[](void* memory, size_t) noexcept { ::operator delete(memory); }

int main() {
#ifdef _MSC_VER
    // Allocation-failure regressions must fail unattended, without modal CRT dialogs.
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
#endif
    // Observe library-owned deallocations, never caller-owned known test buffers.
    // 32 bytes distinguish the actual key buffer from MSVC's 8/16-byte proxies.
    const std::vector<uint8_t> key(32, 0xA5);
    for (bool hardware : {false, true}) {
        bool reachedSuccess = false;
        for (long allocation = 0; allocation < 512; ++allocation) {
            bool failed = false;
            failAfter = allocation;
            watching = true;
            try { AES* object = new AES(key, hardware); delete object; }
            catch (const std::bad_alloc&) { failed = true; }
            watching = false;
            failAfter = -1;
            if (uncleared) {
                std::puts("Constructor exception leaked a raw key copy at deallocation");
                return 1;
            }
            if (!failed) { reachedSuccess = true; break; }
        }
        if (!reachedSuccess) return 2;
        AES aes(key, hardware);
        const std::vector<uint8_t> plaintext(32, 0xA5);
        auto ciphertext = aes.encrypt_gcm_siv(plaintext, {7});
        watching = true;
        bool rejected = false;
        try { aes.decrypt_gcm_siv(ciphertext); }
        catch (const std::runtime_error&) { rejected = true; }
        watching = false;
        if (!rejected || uncleared) {
            std::puts("Authentication failure left a known plaintext copy at deallocation");
            return 3;
        }
    }
    std::puts("Secret-copy cleanup and allocation-failure tests passed");
    return 0;
}
