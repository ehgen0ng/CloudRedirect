#include "cloud_hooks.h"

#include "cloud_intercept.h"
#include "cloud_rpc_utils.h"
#include "cr_api.h"
#include "log.h"
#include "protobuf.h"
#include "rpc_handlers.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <climits>
#include <cstring>
#include <thread>
#include <vector>

namespace {

using YieldingSendFn = int (*)(void*, const char*, void*, void*, int*);
using NotificationFn = int (*)(void*, const char*, void*, int*);
using SyncSendFn = int (*)(void*, const char*, const void*, uint32_t, void*, int*);
using SerializeFn = uint8_t* (*)(void*, uint8_t*);
using ParseFn = int (*)(void*, const void*, int);
using ByteSizeFn = size_t (*)(void*);

constexpr size_t kMaxProtobufSize = 64u * 1024u * 1024u;

std::atomic<YieldingSendFn> g_originalSlot5{nullptr};
std::atomic<NotificationFn> g_originalSlot7{nullptr};
std::atomic<SyncSendFn> g_originalSlot8{nullptr};
std::atomic<SerializeFn> g_serialize{nullptr};
std::atomic<ParseFn> g_parse{nullptr};
std::atomic<bool> g_shuttingDown{false};
std::atomic<uint32_t> g_hookCalls{0};

struct HookCallGuard {
    HookCallGuard() { g_hookCalls.fetch_add(1, std::memory_order_acquire); }
    ~HookCallGuard() { g_hookCalls.fetch_sub(1, std::memory_order_release); }
};

struct PatternPart {
    size_t offset;
    const uint8_t* bytes;
    size_t size;
};

uintptr_t FindUniqueCompositePattern(uintptr_t textStart, size_t textSize,
                                     const PatternPart* parts, size_t partCount,
                                     const char* name) {
    size_t requiredSize = 0;
    for (size_t i = 0; i < partCount; ++i)
        requiredSize = std::max(requiredSize, parts[i].offset + parts[i].size);
    if (requiredSize > textSize) return 0;

    uintptr_t match = 0;
    size_t matchCount = 0;
    for (size_t offset = 0; offset + requiredSize <= textSize; offset += 4) {
        bool matches = true;
        for (size_t i = 0; i < partCount; ++i) {
            if (std::memcmp(reinterpret_cast<const void*>(
                                textStart + offset + parts[i].offset),
                            parts[i].bytes, parts[i].size) != 0) {
                matches = false;
                break;
            }
        }
        if (!matches) continue;
        match = textStart + offset;
        ++matchCount;
        if (matchCount > 1) break;
    }

    if (matchCount != 1) {
        LOG("[macOS Hook] %s ARM64 signature matched %zu locations",
            name, matchCount);
        return 0;
    }
    return match;
}

bool SerializeMessage(void* message, std::vector<uint8_t>& out) {
    out.clear();
    const SerializeFn serialize = g_serialize.load(std::memory_order_acquire);
    if (!message || !serialize) return false;

    void** vtable = *reinterpret_cast<void***>(message);
    if (!vtable || !vtable[9]) return false;
    const size_t size = reinterpret_cast<ByteSizeFn>(vtable[9])(message);
    if (size > kMaxProtobufSize) return false;

    out.resize(std::max<size_t>(size, 1));
    uint8_t* end = serialize(message, out.data());
    if (end != out.data() + size) {
        out.clear();
        return false;
    }
    out.resize(size);
    return true;
}

bool ParseMessage(void* message, const uint8_t* data, size_t size) {
    const ParseFn parse = g_parse.load(std::memory_order_acquire);
    if (!message || !parse || size > static_cast<size_t>(INT_MAX)) return false;
    if (size == 0) return true;
    return parse(message, data, static_cast<int>(size)) != 0;
}

bool IsCloudMethod(const char* method) {
    return method && std::strncmp(method, "Cloud.", 6) == 0;
}

bool Dispatch(const char* method, uint32_t appId,
              const uint8_t* request, uint32_t requestSize,
              void* response, int* flags) {
    static thread_local std::vector<uint8_t> responseBuffer(kMaxProtobufSize);
    uint32_t responseSize = 0;
    int32_t eresult = CloudIntercept::kEResultFail;
    if (!CR_HandleCloudRpc(method, appId, CloudIntercept::GetAccountId(),
                           request, requestSize,
                           responseBuffer.data(),
                           static_cast<uint32_t>(responseBuffer.size()),
                           &responseSize, &eresult)) {
        return false;
    }

    if (responseSize != 0 &&
        !ParseMessage(response, responseBuffer.data(), responseSize)) {
        LOG("[macOS Hook] response parse failed: method=%s app=%u size=%u",
            method, appId, responseSize);
        return false;
    }
    if (flags) {
        flags[2] = 1;
        flags[3] = eresult;
    }
    return true;
}

uint32_t ExtractAppId(const char* method, const uint8_t* data, size_t size) {
    if (!method || (!data && size != 0)) return 0;
    const auto fields = PB::Parse(data, size);
    return CloudRpcUtils::ExtractAppId(method, fields);
}

} // namespace

namespace MacCloudHooks {

bool ResolveProtobufHelpers(uintptr_t textStart,
                            size_t textSize) {
    static constexpr uint8_t kParseHead[] = {
        0xf6, 0x57, 0xbd, 0xa9, 0xf4, 0x4f, 0x01, 0xa9,
        0xfd, 0x7b, 0x02, 0xa9, 0xfd, 0x83, 0x00, 0x91,
    };
    static constexpr uint8_t kParseTail[] = {
        0xf4, 0x03, 0x01, 0xaa, 0xf3, 0x03, 0x00, 0xaa,
        0xf5, 0x03, 0x02, 0x2a, 0x08, 0x00, 0x40, 0xf9,
        0x08, 0x15, 0x40, 0xf9, 0x00, 0x01, 0x3f, 0xd6,
    };
    static constexpr PatternPart kParseParts[] = {
        {0, kParseHead, sizeof(kParseHead)},
        {20, kParseTail, sizeof(kParseTail)},
    };

    static constexpr uint8_t kSerializeHead[] = {
        0xff, 0xc3, 0x02, 0xd1, 0xf6, 0x57, 0x08, 0xa9,
        0xf4, 0x4f, 0x09, 0xa9, 0xfd, 0x7b, 0x0a, 0xa9,
        0xfd, 0x83, 0x02, 0x91, 0xf3, 0x03, 0x01, 0xaa,
        0xf4, 0x03, 0x00, 0xaa,
    };
    static constexpr uint8_t kSerializeTail[] = {
        0x08, 0x01, 0x40, 0xf9, 0xa8, 0x83, 0x1d, 0xf8,
        0x08, 0x00, 0x40, 0xf9, 0x08, 0x29, 0x40, 0xf9,
        0x00, 0x01, 0x3f, 0xd6,
    };
    static constexpr PatternPart kSerializeParts[] = {
        {0, kSerializeHead, sizeof(kSerializeHead)},
        {36, kSerializeTail, sizeof(kSerializeTail)},
    };

    uintptr_t serializeAddress = FindUniqueCompositePattern(
        textStart, textSize, kSerializeParts,
        sizeof(kSerializeParts) / sizeof(kSerializeParts[0]), "serialize helper");
    uintptr_t parseAddress = FindUniqueCompositePattern(
        textStart, textSize, kParseParts,
        sizeof(kParseParts) / sizeof(kParseParts[0]), "parse helper");

    if (!serializeAddress || !parseAddress) {
        LOG("[macOS Hook] protobuf helper resolution failed");
        return false;
    }

    g_serialize.store(reinterpret_cast<SerializeFn>(serializeAddress),
                      std::memory_order_release);
    g_parse.store(reinterpret_cast<ParseFn>(parseAddress),
                  std::memory_order_release);
    g_shuttingDown.store(false, std::memory_order_release);
    LOG("[macOS Hook] protobuf helpers dynamically matched: serialize=%p parse=%p",
        reinterpret_cast<void*>(serializeAddress),
        reinterpret_cast<void*>(parseAddress));
    return true;
}

void SetOriginals(void* slot5, void* slot7, void* slot8) {
    g_originalSlot5.store(reinterpret_cast<YieldingSendFn>(slot5),
                          std::memory_order_release);
    g_originalSlot7.store(reinterpret_cast<NotificationFn>(slot7),
                          std::memory_order_release);
    g_originalSlot8.store(reinterpret_cast<SyncSendFn>(slot8),
                          std::memory_order_release);
}

void BeginShutdown() {
    g_shuttingDown.store(true, std::memory_order_release);
    for (int i = 0; i < 300 && g_hookCalls.load(std::memory_order_acquire) != 0; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    g_serialize.store(nullptr, std::memory_order_release);
    g_parse.store(nullptr, std::memory_order_release);
}

} // namespace MacCloudHooks

extern "C" int MacHook_YieldingSend(void* self, const char* method,
                                     void* request, void* response, int* flags) {
    HookCallGuard guard;
    const YieldingSendFn original = g_originalSlot5.load(std::memory_order_acquire);
    if (!original) return 0;
    if (g_shuttingDown.load(std::memory_order_acquire) || !IsCloudMethod(method))
        return original(self, method, request, response, flags);

    std::vector<uint8_t> requestBytes;
    if (!SerializeMessage(request, requestBytes))
        return original(self, method, request, response, flags);

    const uint32_t appId = ExtractAppId(method, requestBytes.data(), requestBytes.size());
    if (appId == 0 || !CloudIntercept::IsNamespaceApp(appId))
        return original(self, method, request, response, flags);

    int originalResult = 0;
    const bool download = std::strcmp(method, CloudIntercept::RPC_FILE_DOWNLOAD) == 0;
    if (download)
        originalResult = original(self, method, request, response, flags);

    if (!Dispatch(method, appId, requestBytes.data(),
                  static_cast<uint32_t>(requestBytes.size()), response, flags)) {
        return download ? originalResult
                        : original(self, method, request, response, flags);
    }
    LOG("[macOS Hook] intercepted slot5 %s app=%u", method, appId);
    return 1;
}

extern "C" int MacHook_Notification(void* self, const char* method,
                                     void* body, int* flags) {
    HookCallGuard guard;
    const NotificationFn original = g_originalSlot7.load(std::memory_order_acquire);
    if (!original) return 0;
    if (g_shuttingDown.load(std::memory_order_acquire) || !IsCloudMethod(method))
        return original(self, method, body, flags);

    std::vector<uint8_t> bodyBytes;
    if (!SerializeMessage(body, bodyBytes))
        return original(self, method, body, flags);
    const uint32_t appId = ExtractAppId(method, bodyBytes.data(), bodyBytes.size());
    if (appId == 0 || !CloudIntercept::IsNamespaceApp(appId))
        return original(self, method, body, flags);

    const auto fields = PB::Parse(bodyBytes.data(), bodyBytes.size());
    if (std::strcmp(method, CloudIntercept::RPC_CONFLICT) == 0) {
        bool choseLocal = false;
        if (const auto* field = PB::FindField(fields, 2))
            choseLocal = field->varintVal != 0;
        CloudIntercept::RecordConflictResolution(appId, choseLocal);
    }
    if (std::strcmp(method, CloudIntercept::RPC_EXIT_SYNC) == 0) {
        uint8_t responseByte = 0;
        uint32_t responseSize = 0;
        int32_t eresult = CloudIntercept::kEResultFail;
        CR_HandleCloudRpc(method, appId, CloudIntercept::GetAccountId(),
                          bodyBytes.data(), static_cast<uint32_t>(bodyBytes.size()),
                          &responseByte, 1, &responseSize, &eresult);
        return original(self, method, body, flags);
    }

    LOG("[macOS Hook] suppressed notification %s app=%u", method, appId);
    return 1;
}

extern "C" int MacHook_SyncSend(void* self, const char* method,
                                 const void* data, uint32_t size,
                                 void* response, int* flags) {
    HookCallGuard guard;
    const SyncSendFn original = g_originalSlot8.load(std::memory_order_acquire);
    if (!original) return 0;
    if (g_shuttingDown.load(std::memory_order_acquire) || !IsCloudMethod(method) ||
        (!data && size != 0)) {
        return original(self, method, data, size, response, flags);
    }

    const auto* bytes = static_cast<const uint8_t*>(data);
    const uint32_t appId = ExtractAppId(method, bytes, size);
    if (appId == 0 || !CloudIntercept::IsNamespaceApp(appId))
        return original(self, method, data, size, response, flags);

    if (!Dispatch(method, appId, bytes, size, response, flags))
        return original(self, method, data, size, response, flags);
    LOG("[macOS Hook] intercepted slot8 %s app=%u", method, appId);
    return 1;
}
