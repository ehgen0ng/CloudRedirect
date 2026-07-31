#include "vtable_hook.h"

#include "cloud_hooks.h"
#include "log.h"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mutex>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

extern "C" {
int MacHook_YieldingSend(void*, const char*, void*, void*, int*);
int MacHook_Notification(void*, const char*, void*, int*);
int MacHook_SyncSend(void*, const char*, const void*, uint32_t, void*, int*);
}

namespace {

constexpr char kTransportRtti[] = "30CClientUnifiedServiceTransport";

std::atomic<bool> g_installed{false};
std::mutex g_hookMutex;
void** g_vtable = nullptr;
void* g_originalSlot5 = nullptr;
void* g_originalSlot7 = nullptr;
void* g_originalSlot8 = nullptr;

struct ImageLayout {
    uintptr_t base = 0;
    uintptr_t textStart = 0;
    size_t textSize = 0;
    uintptr_t cstringStart = 0;
    size_t cstringSize = 0;
    uintptr_t textConstStart = 0;
    size_t textConstSize = 0;
    uintptr_t constStart = 0;
    size_t constSize = 0;
};

bool NameEquals(const char name[16], const char* expected) {
    return std::strncmp(name, expected, 16) == 0;
}

bool FindSteamclient(ImageLayout& out) {
    const uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; ++i) {
        const char* path = _dyld_get_image_name(i);
        if (!path || !std::strstr(path, "steamclient.dylib")) continue;

        const mach_header* genericHeader = _dyld_get_image_header(i);
        if (!genericHeader || genericHeader->magic != MH_MAGIC_64 ||
            genericHeader->cputype != CPU_TYPE_ARM64) {
            continue;
        }
        const auto* header = reinterpret_cast<const mach_header_64*>(genericHeader);
        const intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        const auto* commands = reinterpret_cast<const uint8_t*>(header + 1);
        size_t offset = 0;

        ImageLayout candidate;
        for (uint32_t commandIndex = 0; commandIndex < header->ncmds; ++commandIndex) {
            if (offset + sizeof(load_command) > header->sizeofcmds) break;
            const auto* command = reinterpret_cast<const load_command*>(commands + offset);
            if (command->cmdsize < sizeof(load_command) ||
                offset + command->cmdsize > header->sizeofcmds) {
                break;
            }
            if (command->cmd == LC_SEGMENT_64 &&
                command->cmdsize >= sizeof(segment_command_64)) {
                const auto* segment = reinterpret_cast<const segment_command_64*>(command);
                if (NameEquals(segment->segname, "__TEXT"))
                    candidate.base = static_cast<uintptr_t>(slide + segment->vmaddr);

                const size_t sectionBytes =
                    static_cast<size_t>(segment->nsects) * sizeof(section_64);
                if (sizeof(segment_command_64) + sectionBytes <= command->cmdsize) {
                    const auto* sections = reinterpret_cast<const section_64*>(segment + 1);
                    for (uint32_t sectionIndex = 0;
                         sectionIndex < segment->nsects; ++sectionIndex) {
                        const auto& section = sections[sectionIndex];
                        const uintptr_t address =
                            static_cast<uintptr_t>(slide + section.addr);
                        if (NameEquals(section.segname, "__TEXT") &&
                            NameEquals(section.sectname, "__text")) {
                            candidate.textStart = address;
                            candidate.textSize = static_cast<size_t>(section.size);
                        } else if (NameEquals(section.segname, "__TEXT") &&
                                   NameEquals(section.sectname, "__cstring")) {
                            candidate.cstringStart = address;
                            candidate.cstringSize = static_cast<size_t>(section.size);
                        } else if (NameEquals(section.segname, "__TEXT") &&
                                   NameEquals(section.sectname, "__const")) {
                            candidate.textConstStart = address;
                            candidate.textConstSize = static_cast<size_t>(section.size);
                        } else if (NameEquals(section.segname, "__DATA_CONST") &&
                                   NameEquals(section.sectname, "__const")) {
                            candidate.constStart = address;
                            candidate.constSize = static_cast<size_t>(section.size);
                        }
                    }
                }
            }
            offset += command->cmdsize;
        }

        if (candidate.base && candidate.textStart && candidate.constStart &&
            (candidate.cstringStart || candidate.textConstStart)) {
            out = std::move(candidate);
            return true;
        }
    }
    return false;
}

const char* FindString(uintptr_t start, size_t size,
                       const char* needle, size_t needleSize) {
    if (!start || size < needleSize) return nullptr;
    const auto* begin = reinterpret_cast<const uint8_t*>(start);
    const auto* end = begin + size - needleSize + 1;
    for (const uint8_t* cursor = begin; cursor < end; ++cursor) {
        if (std::memcmp(cursor, needle, needleSize) == 0)
            return reinterpret_cast<const char*>(cursor);
    }
    return nullptr;
}

const char* FindRttiString(const ImageLayout& image) {
    const size_t nameSize = sizeof(kTransportRtti);
    if (const char* name = FindString(image.cstringStart, image.cstringSize,
                                      kTransportRtti, nameSize)) {
        LOG("[macOS Hook] transport RTTI string found in __TEXT,__cstring");
        return name;
    }
    const char* name = FindString(image.textConstStart, image.textConstSize,
                                  kTransportRtti, nameSize);
    if (name)
        LOG("[macOS Hook] transport RTTI string found in __TEXT,__const");
    return name;
}

bool IsValidTransportVtable(const ImageLayout& image, void** vtable) {
    const uintptr_t address = reinterpret_cast<uintptr_t>(vtable);
    constexpr size_t kRequiredSlots = 9;
    if (image.constSize < kRequiredSlots * sizeof(void*) ||
        address < image.constStart ||
        address - image.constStart >
            image.constSize - kRequiredSlots * sizeof(void*)) {
        return false;
    }

    const uintptr_t slot5 = reinterpret_cast<uintptr_t>(vtable[5]);
    const uintptr_t slot7 = reinterpret_cast<uintptr_t>(vtable[7]);
    const uintptr_t slot8 = reinterpret_cast<uintptr_t>(vtable[8]);
    const auto inText = [&image](uintptr_t function) {
        return function >= image.textStart &&
               function - image.textStart < image.textSize &&
               (function & 3u) == 0;
    };
    return inText(slot5) && inText(slot7) && inText(slot8) &&
           slot5 != slot7 && slot5 != slot8 && slot7 != slot8;
}

void** FindTransportVtable(const ImageLayout& image) {
    const char* name = FindRttiString(image);
    if (!name) {
        Log::Error("transport RTTI string not found");
        return nullptr;
    }

    const uintptr_t nameAddress = reinterpret_cast<uintptr_t>(name);
    const uintptr_t begin = (image.constStart + sizeof(uintptr_t) - 1) &
                            ~(sizeof(uintptr_t) - 1);
    const uintptr_t end = image.constStart + image.constSize;
    std::vector<uintptr_t> typeinfos;
    for (uintptr_t cursor = begin + sizeof(uintptr_t); cursor < end;
         cursor += sizeof(uintptr_t)) {
        if (*reinterpret_cast<const uintptr_t*>(cursor) == nameAddress) {
            const uintptr_t candidate = cursor - sizeof(uintptr_t);
            if (*reinterpret_cast<const uintptr_t*>(candidate) != 0)
                typeinfos.push_back(candidate);
        }
    }
    if (typeinfos.empty()) {
        Log::Error("transport typeinfo not found");
        return nullptr;
    }

    void** match = nullptr;
    size_t matchCount = 0;
    constexpr size_t kVtableWords = 2 + 9;
    if (image.constSize < kVtableWords * sizeof(uintptr_t)) {
        Log::Error("transport vtable section is too small");
        return nullptr;
    }
    const uintptr_t lastCandidate =
        end - kVtableWords * sizeof(uintptr_t);
    for (uintptr_t cursor = begin; cursor <= lastCandidate;
         cursor += sizeof(uintptr_t)) {
        const auto* words = reinterpret_cast<const uintptr_t*>(cursor);
        if (words[0] != 0 ||
            std::find(typeinfos.begin(), typeinfos.end(), words[1]) ==
                typeinfos.end()) {
            continue;
        }
        void** candidate = reinterpret_cast<void**>(
            cursor + 2 * sizeof(uintptr_t));
        if (!IsValidTransportVtable(image, candidate)) continue;
        match = candidate;
        ++matchCount;
    }

    if (matchCount != 1) {
        Log::Error("transport RTTI produced %zu structurally valid vtable candidates",
                   matchCount);
        return nullptr;
    }
    LOG("[macOS Hook] transport vtable dynamically matched at %p", match);
    return match;
}

bool SetVtableWritable(void** vtable, bool writable) {
    const long pageSize = sysconf(_SC_PAGESIZE);
    if (pageSize <= 0) return false;
    const uintptr_t first = reinterpret_cast<uintptr_t>(&vtable[5]);
    const uintptr_t last = reinterpret_cast<uintptr_t>(&vtable[8]) + sizeof(void*);
    const uintptr_t page = first & ~(static_cast<uintptr_t>(pageSize) - 1);
    const size_t length = (last - page + static_cast<size_t>(pageSize) - 1) &
                          ~(static_cast<size_t>(pageSize) - 1);
    const int protection = writable ? (PROT_READ | PROT_WRITE) : PROT_READ;
    return mprotect(reinterpret_cast<void*>(page), length, protection) == 0;
}

bool WriteHooks(void** vtable) {
    if (!SetVtableWritable(vtable, true)) {
        Log::Error("mprotect failed while enabling vtable writes");
        return false;
    }
    __atomic_store_n(&vtable[5], reinterpret_cast<void*>(&MacHook_YieldingSend),
                     __ATOMIC_RELEASE);
    __atomic_store_n(&vtable[7], reinterpret_cast<void*>(&MacHook_Notification),
                     __ATOMIC_RELEASE);
    __atomic_store_n(&vtable[8], reinterpret_cast<void*>(&MacHook_SyncSend),
                     __ATOMIC_RELEASE);
    if (!SetVtableWritable(vtable, false))
        Log::Warn("mprotect failed while restoring vtable read-only protection");
    return true;
}

void RestoreHooks() {
    if (!g_vtable || !SetVtableWritable(g_vtable, true)) return;
    __atomic_store_n(&g_vtable[5], g_originalSlot5, __ATOMIC_RELEASE);
    __atomic_store_n(&g_vtable[7], g_originalSlot7, __ATOMIC_RELEASE);
    __atomic_store_n(&g_vtable[8], g_originalSlot8, __ATOMIC_RELEASE);
    SetVtableWritable(g_vtable, false);
}

} // namespace

bool MacVtableHook::Install() {
    std::lock_guard lock(g_hookMutex);
    if (g_installed.load(std::memory_order_acquire)) return true;

    ImageLayout image;
    if (!FindSteamclient(image)) {
        Log::Error("steamclient.dylib is not loaded");
        return false;
    }

    void** vtable = FindTransportVtable(image);
    if (!vtable) return false;
    if (!MacCloudHooks::ResolveProtobufHelpers(
            image.textStart, image.textSize)) {
        return false;
    }

    g_vtable = vtable;
    g_originalSlot5 = vtable[5];
    g_originalSlot7 = vtable[7];
    g_originalSlot8 = vtable[8];
    MacCloudHooks::SetOriginals(g_originalSlot5, g_originalSlot7, g_originalSlot8);
    if (!WriteHooks(vtable)) {
        g_vtable = nullptr;
        return false;
    }

    g_installed.store(true, std::memory_order_release);
    LOG("[macOS Hook] installed from dynamic match at vtable=%p", vtable);
    return true;
}

void MacVtableHook::Uninstall() {
    std::lock_guard lock(g_hookMutex);
    if (!g_installed.exchange(false, std::memory_order_acq_rel)) return;
    MacCloudHooks::BeginShutdown();
    RestoreHooks();
    g_vtable = nullptr;
    g_originalSlot5 = nullptr;
    g_originalSlot7 = nullptr;
    g_originalSlot8 = nullptr;
    LOG("[macOS Hook] uninstalled");
}

bool MacVtableHook::IsInstalled() {
    return g_installed.load(std::memory_order_acquire);
}
