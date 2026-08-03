#pragma once

#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

namespace RuntimePaths {

struct Layout {
    std::filesystem::path dataRoot;
    std::filesystem::path configFile;
    std::filesystem::path logFile;
    std::filesystem::path storageRoot;
};

enum class MigrationOutcome {
    SourceMissing,
    Migrated,
    RemovedDuplicate,
    Merged,
    ArchivedConflict,
    SkippedReparsePoint,
    Conflict,
    Failed,
};

struct MigrationRecord {
    std::filesystem::path source;
    std::filesystem::path destination;
    MigrationOutcome outcome = MigrationOutcome::SourceMissing;
    std::error_code error;
    std::string detail;
};

struct MigrationReport {
    std::vector<MigrationRecord> records;
};

// Windows layout:
//   config: %APPDATA%\CloudRedirect\config.json
//   data:   %LOCALAPPDATA%\CloudRedirect
bool ResolveLayout(Layout& layout, std::string& error);

// Moves legacy CloudRedirect-owned runtime files out of the Steam directory.
// Conflicting files are preserved below dataRoot\migration-conflicts instead
// of overwriting either copy or leaving the legacy copy beside steam.exe.
MigrationReport MigrateLegacySteamFiles(const std::filesystem::path& steamRoot,
                                        const Layout& layout);

const char* ToString(MigrationOutcome outcome);

} // namespace RuntimePaths
