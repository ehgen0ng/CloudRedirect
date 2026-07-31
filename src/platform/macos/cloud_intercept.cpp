#include "cloud_intercept.h"

#include "log.h"

#include <atomic>
#include <mutex>
#include <unordered_set>

namespace {

std::mutex g_stateMutex;
std::mutex g_appsMutex;
std::string g_steamPath;
std::atomic<uint32_t> g_accountId{0};
std::unordered_set<uint32_t> g_namespaceApps;

} // namespace

namespace CloudIntercept {

bool IsNamespaceApp(uint32_t appId) {
    std::lock_guard lock(g_appsMutex);
    return g_namespaceApps.contains(appId);
}

bool HasNamespaceApps() {
    std::lock_guard lock(g_appsMutex);
    return !g_namespaceApps.empty();
}

std::vector<uint32_t> GetNamespaceApps() {
    std::lock_guard lock(g_appsMutex);
    return {g_namespaceApps.begin(), g_namespaceApps.end()};
}

void AddNamespaceApp(uint32_t appId) {
    if (appId == 0) return;
    std::lock_guard lock(g_appsMutex);
    g_namespaceApps.insert(appId);
}

void RemoveNamespaceApp(uint32_t appId) {
    std::lock_guard lock(g_appsMutex);
    g_namespaceApps.erase(appId);
}

void SetNamespaceApps(const uint32_t* appIds, uint32_t count,
                      size_t* outAdded, size_t* outRemoved) {
    std::unordered_set<uint32_t> replacement;
    if (appIds) {
        for (uint32_t i = 0; i < count; ++i) {
            if (appIds[i] != 0) replacement.insert(appIds[i]);
        }
    }

    std::lock_guard lock(g_appsMutex);
    size_t added = 0;
    size_t removed = 0;
    for (uint32_t appId : replacement) {
        if (!g_namespaceApps.contains(appId)) ++added;
    }
    for (uint32_t appId : g_namespaceApps) {
        if (!replacement.contains(appId)) ++removed;
    }
    g_namespaceApps = std::move(replacement);
    if (outAdded) *outAdded = added;
    if (outRemoved) *outRemoved = removed;
}

std::string GetSteamPath() {
    std::lock_guard lock(g_stateMutex);
    return g_steamPath;
}

void SetSteamPath(const std::string& path) {
    std::lock_guard lock(g_stateMutex);
    g_steamPath = path;
    if (!g_steamPath.empty() && g_steamPath.back() != '/') g_steamPath += '/';
}

uint32_t GetAccountId() {
    return g_accountId.load(std::memory_order_acquire);
}

void SetAccountId(uint32_t accountId) {
    if (accountId == 0) return;
    g_accountId.store(accountId, std::memory_order_release);
}

void Shutdown() {
    {
        std::lock_guard lock(g_appsMutex);
        g_namespaceApps.clear();
    }
    g_accountId.store(0, std::memory_order_release);
    LOG("[macOS] CloudIntercept shutdown");
}

} // namespace CloudIntercept
