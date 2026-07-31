#include "log.h"

#include <cstdarg>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <pthread.h>

namespace {

FILE* g_logFile = nullptr;
pthread_mutex_t g_logMutex = PTHREAD_MUTEX_INITIALIZER;
std::string g_logPath;
constexpr long kMaxLogSize = 10 * 1024 * 1024;

std::string DefaultLogPath() {
    const char* home = std::getenv("HOME");
    std::filesystem::path root = home && home[0]
        ? std::filesystem::path(home)
        : std::filesystem::temp_directory_path();
    root /= "Library/Application Support/CloudRedirect";
    std::error_code ec;
    std::filesystem::create_directories(root, ec);
    return (root / "cloud_redirect.log").string();
}

void TruncateIfNeeded() {
    if (!g_logFile) return;
    long pos = std::ftell(g_logFile);
    if (pos < 0 || pos < kMaxLogSize) return;
    std::fclose(g_logFile);
    g_logFile = nullptr;
    if (!g_logPath.empty()) std::remove(g_logPath.c_str());
    g_logFile = std::fopen(g_logPath.c_str(), "a");
}

void WriteImpl(const char* level, const char* fmt, va_list args) {
    pthread_mutex_lock(&g_logMutex);
    TruncateIfNeeded();

    std::time_t now = std::time(nullptr);
    std::tm local{};
    localtime_r(&now, &local);
    char timestamp[32]{};
    std::strftime(timestamp, sizeof(timestamp), "%H:%M:%S", &local);

    FILE* out = g_logFile ? g_logFile : stderr;
    std::fprintf(out, "[%s][%s] ", timestamp, level);
    std::vfprintf(out, fmt, args);
    std::fputc('\n', out);
    std::fflush(out);
    pthread_mutex_unlock(&g_logMutex);
}

} // namespace

void Log::Init() { Init(nullptr); }

void Log::Init(const char* path) {
    pthread_mutex_lock(&g_logMutex);
    if (g_logFile) {
        pthread_mutex_unlock(&g_logMutex);
        return;
    }

    g_logPath = path && path[0] ? path : DefaultLogPath();
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(g_logPath).parent_path(), ec);
    g_logFile = std::fopen(g_logPath.c_str(), "a");
    if (g_logFile) {
        std::fprintf(g_logFile, "\n------------------------------------------------------------\n");
        std::fflush(g_logFile);
    }
    pthread_mutex_unlock(&g_logMutex);
    Info("=== CloudRedirect macOS ARM64 started ===");
}

void Log::Shutdown() {
    pthread_mutex_lock(&g_logMutex);
    if (g_logFile) std::fclose(g_logFile);
    g_logFile = nullptr;
    pthread_mutex_unlock(&g_logMutex);
}

#define CR_LOG_IMPL(name, level) \
    void Log::name(const char* fmt, ...) { \
        va_list args; \
        va_start(args, fmt); \
        WriteImpl(level, fmt, args); \
        va_end(args); \
    }

CR_LOG_IMPL(Write, "INFO")
CR_LOG_IMPL(Info, "INFO")
CR_LOG_IMPL(Warn, "WARN")
CR_LOG_IMPL(Error, "ERR ")
CR_LOG_IMPL(Debug, "DBG ")

#undef CR_LOG_IMPL
