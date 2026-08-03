#include "runtime_paths.h"

#include "file_util.h"
#include "json.h"

#include <ShlObj.h>
#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <fstream>
#include <iterator>
#include <utility>

namespace RuntimePaths {
namespace {

namespace fs = std::filesystem;

std::error_code Win32Error(DWORD error = GetLastError()) {
    return std::error_code(static_cast<int>(error), std::system_category());
}

fs::path ResolveKnownFolder(REFKNOWNFOLDERID folderId, std::error_code& ec) {
    ec.clear();
    PWSTR raw = nullptr;
    const HRESULT hr = SHGetKnownFolderPath(folderId, KF_FLAG_DEFAULT, nullptr, &raw);
    if (FAILED(hr) || !raw || !raw[0]) {
        if (raw) CoTaskMemFree(raw);
        ec = std::error_code(static_cast<int>(hr), std::system_category());
        return {};
    }

    fs::path path(raw);
    CoTaskMemFree(raw);
    return path;
}

bool EnsureDirectory(const fs::path& path, std::error_code& ec) {
    ec.clear();
    if (path.empty()) {
        ec = std::make_error_code(std::errc::invalid_argument);
        return false;
    }
    fs::create_directories(FileUtil::LongPath(path), ec);
    return !ec;
}

bool EnsureLayoutDirectories(const Layout& layout, std::error_code& ec) {
    if (!EnsureDirectory(layout.dataRoot, ec)) return false;
    if (!EnsureDirectory(layout.configFile.parent_path(), ec)) return false;
    return true;
}

bool IsMissingError(DWORD error) {
    return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}

bool IsRegularFileWithoutReparse(const fs::path& path,
                                 bool& exists,
                                 bool& reparse,
                                 std::error_code& ec) {
    exists = false;
    reparse = false;
    ec.clear();

    const fs::path longPath = FileUtil::LongPath(path);
    const DWORD attrs = GetFileAttributesW(longPath.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        const DWORD error = GetLastError();
        if (IsMissingError(error)) return false;
        ec = Win32Error(error);
        return false;
    }

    exists = true;
    reparse = (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
    return (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 && !reparse;
}

bool FilesEqual(const fs::path& lhs, const fs::path& rhs, std::error_code& ec) {
    ec.clear();
    const fs::path lhsLong = FileUtil::LongPath(lhs);
    const fs::path rhsLong = FileUtil::LongPath(rhs);

    HANDLE lhsHandle = CreateFileW(lhsLong.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (lhsHandle == INVALID_HANDLE_VALUE) {
        ec = Win32Error();
        return false;
    }

    HANDLE rhsHandle = CreateFileW(rhsLong.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (rhsHandle == INVALID_HANDLE_VALUE) {
        ec = Win32Error();
        CloseHandle(lhsHandle);
        return false;
    }

    LARGE_INTEGER lhsSize{}, rhsSize{};
    if (!GetFileSizeEx(lhsHandle, &lhsSize) || !GetFileSizeEx(rhsHandle, &rhsSize)) {
        ec = Win32Error();
        CloseHandle(rhsHandle);
        CloseHandle(lhsHandle);
        return false;
    }
    if (lhsSize.QuadPart != rhsSize.QuadPart) {
        CloseHandle(rhsHandle);
        CloseHandle(lhsHandle);
        return false;
    }

    std::array<unsigned char, 64 * 1024> lhsBuffer{};
    std::array<unsigned char, 64 * 1024> rhsBuffer{};
    bool equal = true;
    for (;;) {
        DWORD lhsRead = 0;
        DWORD rhsRead = 0;
        if (!ReadFile(lhsHandle, lhsBuffer.data(), static_cast<DWORD>(lhsBuffer.size()),
                      &lhsRead, nullptr) ||
            !ReadFile(rhsHandle, rhsBuffer.data(), static_cast<DWORD>(rhsBuffer.size()),
                      &rhsRead, nullptr)) {
            ec = Win32Error();
            equal = false;
            break;
        }
        if (lhsRead != rhsRead ||
            !std::equal(lhsBuffer.begin(), lhsBuffer.begin() + lhsRead,
                        rhsBuffer.begin())) {
            equal = false;
            break;
        }
        if (lhsRead == 0) break;
    }

    CloseHandle(rhsHandle);
    CloseHandle(lhsHandle);
    return equal;
}

fs::path TemporaryPathFor(const fs::path& destination) {
    static std::atomic<unsigned long> sequence{0};
    fs::path temporary = destination;
    temporary += L".migrating." + std::to_wstring(GetCurrentProcessId()) + L"." +
                 std::to_wstring(GetCurrentThreadId()) + L"." +
                 std::to_wstring(sequence.fetch_add(1, std::memory_order_relaxed));
    return temporary;
}

MigrationRecord MoveFileVerified(const fs::path& source, const fs::path& destination) {
    MigrationRecord result{source, destination};
    if (source.empty() || destination.empty()) {
        result.outcome = MigrationOutcome::Failed;
        result.error = std::make_error_code(std::errc::invalid_argument);
        return result;
    }

    bool sourceExists = false;
    bool sourceReparse = false;
    std::error_code ec;
    const bool sourceRegular = IsRegularFileWithoutReparse(
        source, sourceExists, sourceReparse, ec);
    if (!sourceExists && !ec) return result;
    if (ec) {
        result.outcome = MigrationOutcome::Failed;
        result.error = ec;
        return result;
    }
    if (sourceReparse) {
        result.outcome = MigrationOutcome::SkippedReparsePoint;
        result.detail = "source is a reparse point";
        return result;
    }
    if (!sourceRegular) {
        result.outcome = MigrationOutcome::Failed;
        result.error = std::make_error_code(std::errc::invalid_argument);
        result.detail = "source is not a regular file";
        return result;
    }

    bool destinationExists = false;
    bool destinationReparse = false;
    const bool destinationRegular = IsRegularFileWithoutReparse(
        destination, destinationExists, destinationReparse, ec);
    if (ec) {
        result.outcome = MigrationOutcome::Failed;
        result.error = ec;
        return result;
    }
    if (destinationExists) {
        if (!destinationRegular || destinationReparse) {
            result.outcome = MigrationOutcome::Conflict;
            result.detail = "destination is not a regular file";
            return result;
        }
        if (!FilesEqual(source, destination, ec)) {
            result.outcome = ec ? MigrationOutcome::Failed : MigrationOutcome::Conflict;
            result.error = ec;
            result.detail = ec ? "could not compare files" : "destination differs";
            return result;
        }
        if (!DeleteFileW(FileUtil::LongPath(source).c_str())) {
            result.outcome = MigrationOutcome::Failed;
            result.error = Win32Error();
            return result;
        }
        result.outcome = MigrationOutcome::RemovedDuplicate;
        return result;
    }

    if (!EnsureDirectory(destination.parent_path(), ec)) {
        result.outcome = MigrationOutcome::Failed;
        result.error = ec;
        return result;
    }

    const fs::path temporary = TemporaryPathFor(destination);
    const fs::path sourceLong = FileUtil::LongPath(source);
    const fs::path temporaryLong = FileUtil::LongPath(temporary);
    const fs::path destinationLong = FileUtil::LongPath(destination);

    if (!CopyFileW(sourceLong.c_str(), temporaryLong.c_str(), TRUE)) {
        result.outcome = MigrationOutcome::Failed;
        result.error = Win32Error();
        return result;
    }

    HANDLE temporaryHandle = CreateFileW(temporaryLong.c_str(), GENERIC_WRITE,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (temporaryHandle == INVALID_HANDLE_VALUE || !FlushFileBuffers(temporaryHandle)) {
        result.outcome = MigrationOutcome::Failed;
        result.error = Win32Error();
        if (temporaryHandle != INVALID_HANDLE_VALUE) CloseHandle(temporaryHandle);
        DeleteFileW(temporaryLong.c_str());
        return result;
    }
    CloseHandle(temporaryHandle);

    if (!FilesEqual(source, temporary, ec)) {
        DeleteFileW(temporaryLong.c_str());
        result.outcome = MigrationOutcome::Failed;
        result.error = ec ? ec : std::make_error_code(std::errc::io_error);
        result.detail = "temporary copy verification failed";
        return result;
    }

    if (!MoveFileExW(temporaryLong.c_str(), destinationLong.c_str(),
                     MOVEFILE_WRITE_THROUGH)) {
        const DWORD moveError = GetLastError();
        DeleteFileW(temporaryLong.c_str());

        bool racedExists = false;
        bool racedReparse = false;
        const bool racedRegular = IsRegularFileWithoutReparse(
            destination, racedExists, racedReparse, ec);
        if (!ec && racedExists && racedRegular && !racedReparse &&
            FilesEqual(source, destination, ec) && !ec) {
            if (DeleteFileW(sourceLong.c_str())) {
                result.outcome = MigrationOutcome::RemovedDuplicate;
                return result;
            }
            result.outcome = MigrationOutcome::Failed;
            result.error = Win32Error();
            return result;
        }

        result.outcome = racedExists ? MigrationOutcome::Conflict
                                     : MigrationOutcome::Failed;
        result.error = racedExists ? ec : Win32Error(moveError);
        result.detail = racedExists ? "destination appeared during migration"
                                    : "could not publish temporary copy";
        return result;
    }

    if (!FilesEqual(source, destination, ec)) {
        result.outcome = MigrationOutcome::Failed;
        result.error = ec ? ec : std::make_error_code(std::errc::io_error);
        result.detail = "published copy verification failed";
        return result;
    }
    if (!DeleteFileW(sourceLong.c_str())) {
        result.outcome = MigrationOutcome::Failed;
        result.error = Win32Error();
        result.detail = "destination verified but source removal failed";
        return result;
    }

    result.outcome = MigrationOutcome::Migrated;
    return result;
}

void AddRecord(MigrationReport& report, MigrationRecord record) {
    if (record.outcome != MigrationOutcome::SourceMissing)
        report.records.push_back(std::move(record));
}

MigrationRecord ArchiveConflict(const fs::path& source,
                                const fs::path& relativeArchivePath,
                                const Layout& layout,
                                std::string detail) {
    const fs::path archiveRoot = layout.dataRoot / L"migration-conflicts";
    fs::path candidate = archiveRoot / relativeArchivePath;

    for (unsigned int suffix = 0; suffix < 1000; ++suffix) {
        if (suffix != 0) {
            candidate = archiveRoot / relativeArchivePath;
            candidate += L"." + std::to_wstring(suffix);
        }

        MigrationRecord moved = MoveFileVerified(source, candidate);
        if (moved.outcome == MigrationOutcome::Conflict) continue;
        if (moved.outcome == MigrationOutcome::Migrated ||
            moved.outcome == MigrationOutcome::RemovedDuplicate) {
            moved.outcome = MigrationOutcome::ArchivedConflict;
            moved.detail = std::move(detail);
        }
        return moved;
    }

    MigrationRecord failed{source, candidate, MigrationOutcome::Failed};
    failed.error = std::make_error_code(std::errc::file_exists);
    failed.detail = "could not allocate a unique conflict archive path";
    return failed;
}

MigrationRecord MigrateKnownFile(const fs::path& source,
                                 const fs::path& destination,
                                 const fs::path& relativeArchivePath,
                                 const Layout& layout) {
    MigrationRecord result = MoveFileVerified(source, destination);
    if (result.outcome != MigrationOutcome::Conflict) return result;
    return ArchiveConflict(source, relativeArchivePath, layout,
                           "destination differed; legacy file archived");
}

bool ReadTextFile(const fs::path& path, std::string& content) {
    constexpr std::uintmax_t kMaxConfigBytes = 4 * 1024 * 1024;
    std::error_code ec;
    const auto size = fs::file_size(FileUtil::LongPath(path), ec);
    if (ec || size > kMaxConfigBytes) return false;

    std::ifstream input(FileUtil::LongPath(path), std::ios::binary);
    if (!input) return false;
    content.assign(std::istreambuf_iterator<char>(input), {});
    return input.eof();
}

bool WriteJsonVerified(const fs::path& path, const Json::Value& value,
                       std::error_code& ec) {
    ec.clear();
    const std::string serialized = Json::Stringify(value);
    const std::string utf8Path = FileUtil::PathToUtf8(path);
    if (utf8Path.empty() || !FileUtil::AtomicWriteText(utf8Path, serialized)) {
        ec = std::make_error_code(std::errc::io_error);
        return false;
    }

    std::string written;
    if (!ReadTextFile(path, written) ||
        !Json::DeepEqual(Json::Parse(written), value)) {
        ec = std::make_error_code(std::errc::io_error);
        return false;
    }
    return true;
}

void MigrateLegacyConfig(const fs::path& source,
                         const Layout& layout,
                         MigrationReport& report) {
    MigrationRecord direct = MoveFileVerified(source, layout.configFile);
    if (direct.outcome != MigrationOutcome::Conflict) {
        AddRecord(report, std::move(direct));
        return;
    }

    MigrationRecord sourceArchive = ArchiveConflict(
        source, fs::path(L"config") / L"steam-config.json", layout,
        "AppData config already existed; full Steam config archived");
    const fs::path archivedSource = sourceArchive.destination;
    const bool sourcePreserved =
        sourceArchive.outcome == MigrationOutcome::ArchivedConflict;
    AddRecord(report, sourceArchive);
    if (!sourcePreserved) return;

    std::string sourceText;
    std::string destinationText;
    if (!ReadTextFile(archivedSource, sourceText) ||
        !ReadTextFile(layout.configFile, destinationText)) {
        MigrationRecord failed{archivedSource, layout.configFile,
                               MigrationOutcome::Failed};
        failed.error = std::make_error_code(std::errc::io_error);
        failed.detail = "could not read configs for merge";
        AddRecord(report, std::move(failed));
        return;
    }

    Json::Value sourceConfig = Json::Parse(sourceText);
    Json::Value destinationConfig = Json::Parse(destinationText);
    if (sourceConfig.type != Json::Type::Object) {
        MigrationRecord failed{archivedSource, layout.configFile,
                               MigrationOutcome::Failed};
        failed.error = std::make_error_code(std::errc::invalid_argument);
        failed.detail = "legacy Steam config is not a JSON object; archive preserved";
        AddRecord(report, std::move(failed));
        return;
    }

    if (destinationConfig.type != Json::Type::Object) {
        MigrationRecord destinationArchive = ArchiveConflict(
            layout.configFile, fs::path(L"config") / L"appdata-config.json",
            layout, "invalid AppData config archived before replacement");
        const bool destinationPreserved =
            destinationArchive.outcome == MigrationOutcome::ArchivedConflict;
        AddRecord(report, destinationArchive);
        if (!destinationPreserved) return;
        destinationConfig = Json::Object();
    }

    for (const auto& [key, value] : sourceConfig.objVal) {
        if (!destinationConfig.has(key))
            destinationConfig.objVal.emplace(key, value);
    }

    std::error_code writeEc;
    if (!WriteJsonVerified(layout.configFile, destinationConfig, writeEc)) {
        MigrationRecord failed{archivedSource, layout.configFile,
                               MigrationOutcome::Failed};
        failed.error = writeEc;
        failed.detail = "merged config could not be written and verified";
        AddRecord(report, std::move(failed));
        return;
    }

    MigrationRecord merged{archivedSource, layout.configFile,
                           MigrationOutcome::Merged};
    merged.detail = "missing legacy keys merged; AppData values kept on conflicts";
    AddRecord(report, std::move(merged));
}

void MigrateLegacyTree(const fs::path& sourceRoot,
                       const Layout& layout,
                       MigrationReport& report) {
    std::error_code ec;
    if (!fs::is_directory(FileUtil::LongPath(sourceRoot), ec) || ec) return;

    std::vector<fs::path> directories;
    fs::recursive_directory_iterator it(
        FileUtil::LongPath(sourceRoot),
        fs::directory_options::skip_permission_denied, ec);
    const fs::recursive_directory_iterator end;
    while (!ec && it != end) {
        const fs::directory_entry entry = *it;
        const fs::path entryPath = entry.path();
        const fs::path relative = entryPath.lexically_relative(
            FileUtil::LongPath(sourceRoot));

        const DWORD attrs = GetFileAttributesW(entryPath.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            MigrationRecord failed{entryPath, {}, MigrationOutcome::Failed};
            failed.error = Win32Error();
            AddRecord(report, std::move(failed));
            it.increment(ec);
            continue;
        }

        if ((attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            if ((attrs & FILE_ATTRIBUTE_DIRECTORY) != 0)
                it.disable_recursion_pending();
            MigrationRecord skipped{entryPath, {},
                                    MigrationOutcome::SkippedReparsePoint};
            skipped.detail = "legacy entry is a reparse point";
            AddRecord(report, std::move(skipped));
        } else if ((attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            directories.push_back(entryPath);
        } else if (relative != fs::path(L"config.json")) {
            fs::path destination = layout.dataRoot / relative;
            auto component = relative.begin();
            if (component != relative.end() && *component == fs::path(L"blobs")) {
                ++component;
                fs::path storageRelative;
                for (; component != relative.end(); ++component)
                    storageRelative /= *component;
                destination = layout.storageRoot / storageRelative;
            }
            AddRecord(report, MigrateKnownFile(
                entryPath, destination, relative, layout));
        }

        it.increment(ec);
    }
    if (ec) {
        MigrationRecord failed{sourceRoot, layout.dataRoot,
                               MigrationOutcome::Failed};
        failed.error = ec;
        failed.detail = "legacy directory enumeration failed";
        AddRecord(report, std::move(failed));
    }

    std::sort(directories.begin(), directories.end(),
        [](const fs::path& lhs, const fs::path& rhs) {
            return lhs.native().size() > rhs.native().size();
        });
    for (const auto& directory : directories) {
        ec.clear();
        fs::remove(directory, ec); // only removes empty directories
    }
    ec.clear();
    fs::remove(FileUtil::LongPath(sourceRoot), ec);
}

} // namespace

bool ResolveLayout(Layout& layout, std::string& error) {
    layout = {};
    error.clear();

    std::error_code ec;
    const fs::path localAppData = ResolveKnownFolder(FOLDERID_LocalAppData, ec);
    if (ec || localAppData.empty()) {
        error = "could not resolve %LOCALAPPDATA%";
        if (ec) error += ": " + ec.message();
        return false;
    }

    const fs::path roamingAppData = ResolveKnownFolder(FOLDERID_RoamingAppData, ec);
    if (ec || roamingAppData.empty()) {
        error = "could not resolve %APPDATA%";
        if (ec) error += ": " + ec.message();
        return false;
    }

    layout.dataRoot = localAppData / L"CloudRedirect";
    layout.configFile = roamingAppData / L"CloudRedirect" / L"config.json";
    layout.logFile = layout.dataRoot / L"cloud_redirect.log";
    layout.storageRoot = layout.dataRoot / L"storage";

    if (!EnsureLayoutDirectories(layout, ec)) {
        error = "could not create CloudRedirect user directories: " + ec.message();
        return false;
    }
    return true;
}

MigrationReport MigrateLegacySteamFiles(const fs::path& steamRoot,
                                        const Layout& layout) {
    MigrationReport report;
    std::error_code ec;
    if (steamRoot.empty() || layout.dataRoot.empty() || layout.configFile.empty() ||
        layout.logFile.empty() || layout.storageRoot.empty() ||
        !EnsureLayoutDirectories(layout, ec)) {
        MigrationRecord failed{steamRoot, layout.dataRoot,
                               MigrationOutcome::Failed};
        failed.error = ec ? ec : std::make_error_code(std::errc::invalid_argument);
        failed.detail = "invalid migration layout";
        AddRecord(report, std::move(failed));
        return report;
    }

    const fs::path normalizedSteamRoot = steamRoot.lexically_normal();
    const fs::path legacyRoot = normalizedSteamRoot / L"cloud_redirect";
    const fs::path legacyRootLong = FileUtil::LongPath(legacyRoot);
    const DWORD legacyAttrs = GetFileAttributesW(legacyRootLong.c_str());
    if (legacyAttrs == INVALID_FILE_ATTRIBUTES) {
        const DWORD legacyError = GetLastError();
        if (!IsMissingError(legacyError)) {
            MigrationRecord failed{legacyRoot, layout.dataRoot,
                                   MigrationOutcome::Failed};
            failed.error = Win32Error(legacyError);
            failed.detail = "could not inspect legacy CloudRedirect root";
            AddRecord(report, std::move(failed));
        }
    } else if ((legacyAttrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        MigrationRecord skipped{legacyRoot, {},
                                MigrationOutcome::SkippedReparsePoint};
        skipped.detail = "legacy CloudRedirect root is a reparse point";
        AddRecord(report, std::move(skipped));
    } else if ((legacyAttrs & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        MigrationRecord conflict{legacyRoot, layout.dataRoot,
                                 MigrationOutcome::Conflict};
        conflict.detail = "legacy CloudRedirect root is not a directory";
        AddRecord(report, std::move(conflict));
    } else {
        MigrateLegacyConfig(legacyRoot / L"config.json", layout, report);
        MigrateLegacyTree(legacyRoot, layout, report);
    }
    AddRecord(report, MigrateKnownFile(
        normalizedSteamRoot / L"cloud_redirect.log", layout.logFile,
        fs::path(L"logs") / L"cloud_redirect.log", layout));
    AddRecord(report, MigrateKnownFile(
        normalizedSteamRoot / L"config" / L"stplug-in" / L".sync_state",
        layout.dataRoot / L"lua_sync_state",
        fs::path(L"state") / L"lua_sync_state", layout));
    return report;
}

const char* ToString(MigrationOutcome outcome) {
    switch (outcome) {
    case MigrationOutcome::SourceMissing:       return "source-missing";
    case MigrationOutcome::Migrated:            return "migrated";
    case MigrationOutcome::RemovedDuplicate:    return "removed-duplicate";
    case MigrationOutcome::Merged:              return "merged";
    case MigrationOutcome::ArchivedConflict:    return "archived-conflict";
    case MigrationOutcome::SkippedReparsePoint: return "skipped-reparse-point";
    case MigrationOutcome::Conflict:            return "conflict";
    case MigrationOutcome::Failed:              return "failed";
    }
    return "unknown";
}

} // namespace RuntimePaths
