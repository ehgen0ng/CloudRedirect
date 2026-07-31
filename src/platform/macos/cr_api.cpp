#define CR_API_EXPORTS
#include "cr_api.h"

#include "app_state.h"
#include "cloud_intercept.h"
#include "cloud_storage.h"
#include "http_server.h"
#include "json.h"
#include "local_disk_provider.h"
#include "local_metadata_store.h"
#include "local_storage.h"
#include "log.h"
#include "metadata_sync.h"
#include "pending_ops_journal.h"
#include "protobuf.h"
#include "rpc_handlers.h"
#include "stats_handlers.h"
#include "stats_store.h"
#include "vtable_hook.h"

#include <atomic>
#include <condition_variable>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>

#ifndef CR_VERSION_STRING
#define CR_VERSION_STRING "0.0.0+unknown"
#endif

namespace {

std::mutex g_initMutex;
std::atomic<bool> g_initialized{false};
std::atomic<bool> g_statsApiActive{false};
CR_NotifyFn g_notify = nullptr;

std::atomic<bool>& ShutdownComplete() {
    // A host dylib may call CR_Shutdown after this dylib's static destructors.
    // Keep the idempotence flag alive for the full process lifetime so that
    // late calls return before touching destroyed mutexes or other state.
    static auto* complete = new std::atomic<bool>(false);
    return *complete;
}

std::mutex g_seedMutex;
std::condition_variable g_seedCv;
bool g_seedPending = false;
bool g_seedStop = false;
std::thread g_seedThread;

struct ProcessExitGuard final {
    ~ProcessExitGuard() { CR_Shutdown(); }
};

void EnsureProcessExitGuard() {
    // The host lives in a different dylib, whose static exit guard can run
    // after this dylib's globals. Register our guard after load-time statics so
    // worker threads are stopped before their containers are destroyed.
    static ProcessExitGuard guard;
    (void)guard;
}

std::string ApplicationSupportRoot() {
    const char* home = std::getenv("HOME");
    if (!home || !home[0]) return {};
    return (std::filesystem::path(home) /
            "Library/Application Support/CloudRedirect").string();
}

void Notify(int level, const char* message) {
    if (g_notify) {
        g_notify(level, "CloudRedirect", message);
        return;
    }
    if (level == CR_NOTIFY_ERROR) Log::Error("%s", message);
    else if (level == CR_NOTIFY_WARN) Log::Warn("%s", message);
    else Log::Info("%s", message);
}

bool ReadFolderConfig(const std::string& root,
                      std::string& syncPath,
                      int& maxUploadMb,
                      bool& syncAchievements) {
    const std::filesystem::path configPath =
        std::filesystem::path(root) / "config.json";
    std::ifstream input(configPath);
    if (!input) {
        Notify(CR_NOTIFY_ERROR,
               "config.json was not found in ~/Library/Application Support/CloudRedirect");
        return false;
    }

    std::string content((std::istreambuf_iterator<char>(input)), {});
    Json::Value config = Json::Parse(content);
    if (config.type != Json::Type::Object) {
        Notify(CR_NOTIFY_ERROR, "config.json is not a valid JSON object");
        return false;
    }

    if (config["provider"].str() != "folder") {
        Notify(CR_NOTIFY_ERROR,
               "macOS ARM64 currently supports only provider=folder");
        return false;
    }

    syncPath = config["sync_path"].str();
    if (syncPath.empty() || !std::filesystem::path(syncPath).is_absolute()) {
        Notify(CR_NOTIFY_ERROR, "folder sync_path must be an absolute path");
        return false;
    }

    maxUploadMb = 256;
    if (config["max_upload_mb"].type == Json::Type::Number) {
        const int value = static_cast<int>(config["max_upload_mb"].integer());
        if (value > 0 && value <= 4096) maxUploadMb = value;
    }
    syncAchievements = true;
    if (config["sync_achievements"].type == Json::Type::Bool)
        syncAchievements = config["sync_achievements"].boolean();
    return true;
}

void ConfigureAchievementStore(const std::string& root,
                               const std::string& steamPath) {
    StatsStore::SetCloudProvider(
        [](std::unordered_map<uint32_t, std::string>& out) -> bool {
            const uint32_t accountId = CloudIntercept::GetAccountId();
            if (accountId == 0) return false;

            std::vector<uint8_t> data;
            if (!CloudStorage::DownloadCloudMetadataWithLegacyFallback(
                    accountId, CloudIntercept::kAccountScopeAppId,
                    "stats.json", nullptr, data) || data.empty()) {
                return true;
            }

            Json::Value rootValue = Json::Parse(std::string(
                reinterpret_cast<const char*>(data.data()), data.size()));
            if (rootValue.type != Json::Type::Object) return true;
            for (const auto& [appIdText, appValue] : rootValue.objVal) {
                const uint32_t appId = static_cast<uint32_t>(
                    std::strtoul(appIdText.c_str(), nullptr, 10));
                if (appId != 0) out[appId] = Json::Stringify(appValue);
            }
            return true;
        },
        [](const std::unordered_map<uint32_t, std::string>& all) {
            CloudStorage::InflightSyncScope guard;
            if (!guard) return;

            const uint32_t accountId = CloudIntercept::GetAccountId();
            if (accountId == 0) return;

            Json::Value rootValue = Json::Object();
            std::vector<uint8_t> current;
            if (CloudStorage::DownloadCloudMetadataWithLegacyFallback(
                    accountId, CloudIntercept::kAccountScopeAppId,
                    "stats.json", nullptr, current) && !current.empty()) {
                Json::Value parsed = Json::Parse(std::string(
                    reinterpret_cast<const char*>(current.data()), current.size()));
                if (parsed.type == Json::Type::Object)
                    rootValue = std::move(parsed);
            }

            const auto resetApps = StatsStore::ConsumeResetApps();
            bool changed = false;
            for (const auto& [appId, json] : all) {
                if (appId == 0) continue;
                const std::string key = std::to_string(appId);
                const std::string base = rootValue.has(key)
                    ? Json::Stringify(rootValue.objVal[key]) : std::string();
                const std::string merged = resetApps.contains(appId)
                    ? json : StatsStore::MergeAppStatsJson(base, json);
                Json::Value appValue = Json::Parse(merged);
                if (!rootValue.has(key) ||
                    !Json::DeepEqual(rootValue.objVal[key], appValue)) {
                    rootValue.objVal[key] = std::move(appValue);
                    changed = true;
                }
            }
            if (changed) {
                CloudStorage::UploadCloudMetadataTextAsync(
                    accountId, CloudIntercept::kAccountScopeAppId,
                    "stats.json", Json::Stringify(rootValue));
            }
        },
        [](uint32_t appId) -> std::string {
            CloudStorage::InflightSyncScope guard;
            if (!guard) return {};
            const uint32_t accountId = CloudIntercept::GetAccountId();
            if (accountId == 0) return {};

            std::vector<uint8_t> data;
            if (!CloudStorage::DownloadCloudMetadataWithLegacyFallback(
                    accountId, appId, "stats.json", nullptr, data) || data.empty()) {
                return {};
            }
            return std::string(reinterpret_cast<const char*>(data.data()), data.size());
        });

    StatsHandlers::SetNamespacePredicate(
        [](uint32_t appId) { return CloudIntercept::IsNamespaceApp(appId); });
    StatsStore::SetNamespacePredicate(
        [](uint32_t appId) { return CloudIntercept::IsNamespaceApp(appId); });
    StatsStore::SetAccountIdProvider(
        [] { return CloudIntercept::GetAccountId(); });
    StatsStore::Init(root, steamPath);
    StatsHandlers::Init();
}

void SeedWorker() {
    std::unique_lock lock(g_seedMutex);
    for (;;) {
        g_seedCv.wait(lock, [] { return g_seedPending || g_seedStop; });
        if (g_seedStop) return;
        g_seedPending = false;
        lock.unlock();

        if (g_initialized.load(std::memory_order_acquire) &&
            MetadataSync::syncAchievements.load(std::memory_order_relaxed) &&
            CloudIntercept::GetAccountId() != 0) {
            const auto apps = CloudIntercept::GetNamespaceApps();
            if (!apps.empty()) StatsStore::SeedApps(apps);
        }

        lock.lock();
    }
}

void StartSeedWorker() {
    std::lock_guard lock(g_seedMutex);
    g_seedStop = false;
    g_seedPending = false;
    g_seedThread = std::thread(SeedWorker);
}

void QueueStatsSeed() {
    if (!MetadataSync::syncAchievements.load(std::memory_order_relaxed) ||
        CloudIntercept::GetAccountId() == 0 ||
        !CloudIntercept::HasNamespaceApps()) {
        return;
    }
    {
        std::lock_guard lock(g_seedMutex);
        if (g_seedStop) return;
        g_seedPending = true;
    }
    g_seedCv.notify_one();
}

void StopSeedWorker() {
    {
        std::lock_guard lock(g_seedMutex);
        g_seedStop = true;
        g_seedPending = false;
    }
    g_seedCv.notify_one();
    if (g_seedThread.joinable()) g_seedThread.join();
}

std::optional<CloudIntercept::RpcResult> DispatchCloudRpc(
    const char* method, uint32_t appId, const std::vector<PB::Field>& fields) {
    using namespace CloudIntercept;
    if (std::strcmp(method, RPC_GET_CHANGELIST) == 0) return HandleGetChangelist(appId, fields);
    if (std::strcmp(method, RPC_LAUNCH_INTENT) == 0) return HandleLaunchIntent(appId, fields);
    if (std::strcmp(method, RPC_SUSPEND_SESSION) == 0) return HandleSuspendSession(appId, fields);
    if (std::strcmp(method, RPC_RESUME_SESSION) == 0) return HandleResumeSession(appId, fields);
    if (std::strcmp(method, RPC_QUOTA_USAGE) == 0) return HandleQuotaUsage(appId, fields);
    if (std::strcmp(method, RPC_BEGIN_BATCH) == 0) return HandleBeginBatch(appId, fields);
    if (std::strcmp(method, RPC_BEGIN_UPLOAD) == 0) return HandleBeginFileUpload(appId, fields);
    if (std::strcmp(method, RPC_COMMIT_UPLOAD) == 0) return HandleCommitFileUpload(appId, fields);
    if (std::strcmp(method, RPC_COMPLETE_BATCH) == 0) return HandleCompleteBatch(appId, fields);
    if (std::strcmp(method, RPC_FILE_DOWNLOAD) == 0) return HandleFileDownload(appId, fields);
    if (std::strcmp(method, RPC_DELETE_FILE) == 0) return HandleDeleteFile(appId, fields);
    if (std::strcmp(method, StatsHandlers::RPC_GET_USER_STATS) == 0 &&
        MetadataSync::syncAchievements.load(std::memory_order_relaxed)) {
        return StatsHandlers::HandleGetUserStats(appId, fields);
    }
    return std::nullopt;
}

} // namespace

extern "C" __attribute__((visibility("default")))
const char* CR_GetVersion() {
    return CR_VERSION_STRING;
}

extern "C" void CR_SetCrashContext(const char*, const char*, uint32_t) {}
extern "C" void CR_ClearCrashContext() {}

bool CR_InitCloudSave(const char* steamPath, CR_NotifyFn notify) {
    if (!steamPath || !steamPath[0]) return false;
    if (g_initialized.load(std::memory_order_acquire)) return true;

    std::lock_guard lock(g_initMutex);
    if (g_initialized.load(std::memory_order_relaxed)) return true;
    ShutdownComplete().store(false, std::memory_order_release);
    g_notify = notify;

    const std::string root = ApplicationSupportRoot();
    if (root.empty()) {
        Notify(CR_NOTIFY_ERROR, "HOME is not available; cannot locate CloudRedirect configuration");
        return false;
    }

    std::error_code ec;
    std::filesystem::create_directories(root, ec);
    if (ec) {
        Notify(CR_NOTIFY_ERROR, "failed to create CloudRedirect application support directory");
        return false;
    }
    Log::Init((std::filesystem::path(root) / "cloud_redirect.log").c_str());

    std::string syncPath;
    int maxUploadMb = 256;
    bool syncAchievements = true;
    if (!ReadFolderConfig(root, syncPath, maxUploadMb, syncAchievements)) return false;

    auto provider = std::make_unique<LocalDiskProvider>();
    if (!provider->Init(syncPath)) {
        Notify(CR_NOTIFY_ERROR, "failed to initialize folder provider at sync_path");
        return false;
    }

    CloudIntercept::SetSteamPath(steamPath);
    MetadataSync::syncAchievements.store(syncAchievements, std::memory_order_relaxed);
    MetadataSync::syncPlaytime.store(false, std::memory_order_relaxed);
    MetadataSync::schemaFetch.store(false, std::memory_order_relaxed);

    const std::string storageRoot =
        (std::filesystem::path(root) / "storage").string();
    CloudStorage::Init(root, std::move(provider));
    LocalStorage::Init(storageRoot);
    LocalMetadataStore::Init(storageRoot);
    PendingOpsJournal::Init(storageRoot);
    ConfigureAchievementStore(root, CloudIntercept::GetSteamPath());
    HttpServer::SetMaxUploadMB(maxUploadMb);
    if (!HttpServer::Start(storageRoot, 0)) {
        CloudStorage::Shutdown();
        Notify(CR_NOTIFY_ERROR, "failed to start the local blob HTTP server");
        return false;
    }

    g_initialized.store(true, std::memory_order_release);
    EnsureProcessExitGuard();
    StartSeedWorker();
    LOG("[macOS] CR_InitCloudSave complete: steam=%s sync=%s",
        CloudIntercept::GetSteamPath().c_str(), syncPath.c_str());
    return true;
}

bool CR_HandleCloudRpc(const char* method, uint32_t appId,
                       uint32_t accountId,
                       const uint8_t* reqBody, uint32_t reqLen,
                       uint8_t* respBuf, uint32_t respMaxLen,
                       uint32_t* respLen, int32_t* eresult) {
    if (!respLen || !eresult) return false;
    *respLen = 0;
    *eresult = CloudIntercept::kEResultFail;
    if (!g_initialized.load(std::memory_order_acquire) || !method || !respBuf) return false;
    if (!reqBody && reqLen != 0) return false;
    if (!CloudIntercept::IsNamespaceApp(appId)) return false;

    if (accountId != 0) {
        CloudIntercept::SetAccountId(accountId);
        HttpServer::SetAccountId(accountId);
    }
    if (CloudIntercept::GetAccountId() == 0) return false;

    LocalStorage::InitApp(CloudIntercept::GetAccountId(), appId);
    LocalMetadataStore::InitApp(CloudIntercept::GetAccountId(), appId);

    auto fields = PB::Parse(reqBody, reqLen);
    if (std::strcmp(method, CloudIntercept::RPC_EXIT_SYNC) == 0) {
        uint64_t clientId = 0;
        bool uploadsCompleted = false;
        bool uploadsRequired = false;
        if (auto* field = PB::FindField(fields, 2)) clientId = field->varintVal;
        if (auto* field = PB::FindField(fields, 3)) uploadsCompleted = field->varintVal != 0;
        if (auto* field = PB::FindField(fields, 4)) uploadsRequired = field->varintVal != 0;
        const uint32_t activeAccount = CloudIntercept::GetAccountId();
        PendingOpsJournal::RecordExitSyncState(activeAccount, appId,
                                               uploadsCompleted, uploadsRequired, clientId);
        std::thread([activeAccount, appId, clientId] {
            CloudStorage::InflightSyncScope guard;
            if (guard) CloudStorage::ReleaseCloudSession(activeAccount, appId, clientId);
        }).detach();
        *eresult = CloudIntercept::kEResultOK;
        return true;
    }

    auto result = DispatchCloudRpc(method, appId, fields);
    if (!result) return false;
    const auto& bytes = result->body.Data();
    if (bytes.size() > respMaxLen) return false;
    if (!bytes.empty()) std::memcpy(respBuf, bytes.data(), bytes.size());
    *respLen = static_cast<uint32_t>(bytes.size());
    *eresult = result->eresult;
    return true;
}

// OpenSteamTool owns the complete redirected-app set and updates it through
// CR_SetApps. Keep the legacy incremental ABI exports as intentional no-ops.
void CR_AddApp(uint32_t) {}
void CR_RemoveApp(uint32_t) {}
bool CR_IsApp(uint32_t appId) { return CloudIntercept::IsNamespaceApp(appId); }

void CR_SetAccountId(uint32_t accountId) {
    if (accountId == 0) return;
    CloudIntercept::SetAccountId(accountId);
    HttpServer::SetAccountId(accountId);
    if (g_initialized.load(std::memory_order_acquire) &&
        MetadataSync::syncAchievements.load(std::memory_order_relaxed)) {
        StatsStore::ResetForAccountSwitch(accountId);
        QueueStatsSeed();
    }
}

void CR_SetApps(const uint32_t* appIds, uint32_t count) {
    CloudIntercept::SetNamespaceApps(appIds, count);
    QueueStatsSeed();
}

void CR_DrainPlaytimeUpdates() {}

void CR_Shutdown() {
    if (ShutdownComplete().load(std::memory_order_acquire)) return;

    std::lock_guard lock(g_initMutex);
    if (ShutdownComplete().load(std::memory_order_relaxed)) return;
    if (!g_initialized.exchange(false, std::memory_order_acq_rel)) {
        ShutdownComplete().store(true, std::memory_order_release);
        return;
    }
    MacVtableHook::Uninstall();
    StopSeedWorker();
    HttpServer::Stop();
    StatsHandlers::Shutdown();
    CloudIntercept::ShutdownRpcHandlers();
    CloudStorage::Shutdown();
    CloudIntercept::Shutdown();
    Log::Shutdown();
    g_statsApiActive.store(false, std::memory_order_relaxed);
    g_notify = nullptr;
    ShutdownComplete().store(true, std::memory_order_release);
}

bool CR_InstallVtableHooks() {
    return g_initialized.load(std::memory_order_acquire) && MacVtableHook::Install();
}

void CR_EnableStatsSync(bool achievements, bool) {
    g_statsApiActive.store(achievements, std::memory_order_release);
    MetadataSync::steamToolsPresent.store(true, std::memory_order_relaxed);
    LOG("[macOS] StatsSync host active: achievements=%d configured=%d playtime=0",
        achievements ? 1 : 0,
        MetadataSync::syncAchievements.load(std::memory_order_relaxed) ? 1 : 0);
    QueueStatsSeed();
}
void CR_NotifyAppRunning(uint32_t, bool) {}
void CR_NotifyStatsStored(uint32_t appId) {
    CR_NotifyStatsStoredFrom(appId, appId);
}
void CR_NotifyStatsStoredFrom(uint32_t appId, uint32_t nativeAppId) {
    if (!g_initialized.load(std::memory_order_acquire) ||
        !g_statsApiActive.load(std::memory_order_acquire) ||
        !MetadataSync::syncAchievements.load(std::memory_order_relaxed) ||
        !CloudIntercept::IsNamespaceApp(appId) || nativeAppId == 0) {
        return;
    }
    StatsStore::CaptureNativeUnlocksFrom(appId, nativeAppId);
}
bool CR_GetPlaytime(uint32_t, CR_PlaytimeInfo*) { return false; }
uint32_t CR_GetAchievements(uint32_t appId, CR_AchievementBlock* out,
                            uint32_t maxBlocks) {
    if (!out || maxBlocks == 0 ||
        !g_initialized.load(std::memory_order_acquire) ||
        !g_statsApiActive.load(std::memory_order_acquire) ||
        !MetadataSync::syncAchievements.load(std::memory_order_relaxed) ||
        !CloudIntercept::IsNamespaceApp(appId)) {
        return 0;
    }

    const StatsStore::AppStats stats = StatsStore::Snapshot(appId);
    uint32_t count = 0;
    for (const auto& block : stats.achievements) {
        if (count == maxBlocks) break;
        out[count].statId = block.statId;
        out[count].bits = block.bits;
        std::copy(std::begin(block.unlockTimes), std::end(block.unlockTimes),
                  std::begin(out[count].unlockTimes));
        ++count;
    }
    return count;
}
