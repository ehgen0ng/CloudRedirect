#include "common.h"
#include "log.h"
#include "cloud_intercept.h"
#include "metadata_sync.h"
#include "file_util.h"
#include "cli.h"
#include "steam_kv_injector.h"
#include "runtime_paths.h"
#include <atomic>
#include <filesystem>
#include <mutex>

static HMODULE g_thisModule = nullptr;
static std::once_flag g_initFlag;

static void LogMigrationReport(const RuntimePaths::MigrationReport& report) {
    for (const auto& record : report.records) {
        const std::string source = FileUtil::PathToUtf8(record.source);
        const std::string destination = FileUtil::PathToUtf8(record.destination);
        if (record.error) {
            LOG("[Migration] %s: %s -> %s (error=%d: %s; %s)",
                RuntimePaths::ToString(record.outcome), source.c_str(),
                destination.c_str(), record.error.value(),
                record.error.message().c_str(), record.detail.c_str());
        } else if (!record.detail.empty()) {
            LOG("[Migration] %s: %s -> %s (%s)",
                RuntimePaths::ToString(record.outcome), source.c_str(),
                destination.c_str(), record.detail.c_str());
        } else {
            LOG("[Migration] %s: %s -> %s",
                RuntimePaths::ToString(record.outcome), source.c_str(),
                destination.c_str());
        }
    }
}

// Steam dir from the DLL's own location, UTF-8.
// All "narrow" std::string paths in the DLL are UTF-8; ACP narrowing here
// would corrupt every non-ASCII Steam install.
static std::string GetSteamPath() {
    wchar_t wdllPath[MAX_PATH];
    DWORD n = GetModuleFileNameW(g_thisModule, wdllPath, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return {};

    // Trim to parent on wide data so we don't split a multi-byte sequence.
    DWORD endIdx = n;
    for (DWORD i = n; i > 0; --i) {
        if (wdllPath[i - 1] == L'\\') { endIdx = i; break; }
    }

    // WideToUtf8 rejects ill-formed UTF-16 (init then logs+skips).
    return FileUtil::WideToUtf8(wdllPath, (size_t)endIdx);
}

// Entry point from the SteamTools payload code cave.
// Returns nonzero if we handled the packet; zero lets Steam's SendPkt run.
extern "C" __declspec(dllexport)
int CloudOnSendPkt(void* thisptr, const uint8_t* data, uint32_t size, void* recvPktFn) {
    // One-time init; init failure -> return 0 (let Steam handle).
    static std::atomic<bool> g_initFailed{false};
    std::call_once(g_initFlag, [&]() {
        try {
            std::string steamPath = GetSteamPath();
            const std::filesystem::path steamRoot = FileUtil::Utf8ToPath(steamPath);
            if (steamRoot.empty()) {
                OutputDebugStringA("CloudRedirect could not resolve the Steam path");
                g_initFailed.store(true, std::memory_order_relaxed);
                return;
            }
            RuntimePaths::Layout layout;
            std::string layoutError;
            if (!RuntimePaths::ResolveLayout(layout, layoutError)) {
                const std::string message = "CloudRedirect path setup failed: " + layoutError;
                OutputDebugStringA(message.c_str());
                g_initFailed.store(true, std::memory_order_relaxed);
                return;
            }
            RuntimePaths::MigrationReport migration =
                RuntimePaths::MigrateLegacySteamFiles(steamRoot, layout);

            const std::string logPath = FileUtil::PathToUtf8(layout.logFile);
            const std::string cloudRoot = FileUtil::PathToUtf8(layout.dataRoot);
            const std::string configPath = FileUtil::PathToUtf8(layout.configFile);
            if (logPath.empty() || cloudRoot.empty() || configPath.empty()) {
                OutputDebugStringA("CloudRedirect path UTF-8 conversion failed");
                g_initFailed.store(true, std::memory_order_relaxed);
                return;
            }

            Log::Init(logPath.c_str());
            MetadataSync::steamToolsPresent.store(true, std::memory_order_relaxed);
            LOG("CloudRedirect loaded via code cave, PID=%u", GetCurrentProcessId());
            LOG("Steam path: %s", steamPath.c_str());
            LOG("Data root: %s", cloudRoot.c_str());
            LOG("Config path: %s", configPath.c_str());
            LogMigrationReport(migration);

            // Module bases (for IDA mapping).
            HMODULE hSteamClient = GetModuleHandleA("steamclient64.dll");
            LOG("steamclient64.dll base: %p", hSteamClient);

            CloudIntercept::Init(steamPath, cloudRoot, configPath,
                                 /*cloudSaveOnly=*/false);

            if (recvPktFn) {
                CloudIntercept::SetSendPktAddr(recvPktFn);
            }

            CloudIntercept::InstallRecvPktDetour();

            CloudIntercept::InstallManifestPinHook();

            CloudIntercept::InstallReleaseStateNop();

            CloudIntercept::InstallManifestEndpointOverride();

            CloudIntercept::InstallGamesPlayedHook();

            LOG("CloudRedirect fully initialized with hooks");
        } catch (const std::exception& ex) {
            LOG("CloudRedirect init FAILED: %s", ex.what());
            g_initFailed.store(true, std::memory_order_relaxed);
        } catch (...) {
            LOG("CloudRedirect init FAILED: unknown exception");
            g_initFailed.store(true, std::memory_order_relaxed);
        }
    });

    if (g_initFailed.load(std::memory_order_relaxed)) return 0;
    return CloudIntercept::OnSendPkt(thisptr, data, size) ? 1 : 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        g_thisModule = hModule;
        DisableThreadLibraryCalls(hModule);

        // Pin against FreeLibrary so hook threads survive.
        {
            HMODULE pinned = nullptr;
            GetModuleHandleExA(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                reinterpret_cast<LPCSTR>(&DllMain),
                &pinned);
        }
        break;

    case DLL_PROCESS_DETACH:
        // FreeLibrary path only (we're pinned, so unreachable today). ExitProcess
        // path runs from an atexit hook installed in CloudIntercept::Init.
        if (reserved == nullptr) {
            CloudIntercept::Shutdown();
        }
        break;
    }
    return TRUE;
}
