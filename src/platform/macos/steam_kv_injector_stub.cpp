#include "steam_kv_injector.h"

namespace SteamKvInjector {

void Configure(const ResolvedKvAddrs&) {}
bool Init() { return false; }
bool IsReady() { return false; }
bool ReadAppQuota(uint32_t, uint64_t&, uint32_t&) { return false; }
bool InjectAppQuota(uint32_t, uint64_t, uint32_t) { return false; }
bool EnsureMaxNumFilesFloor(uint32_t, uint32_t, uint64_t) { return false; }
bool InjectSaveFiles(uint32_t, const std::vector<SaveFileRule>&) { return false; }
void** GetEngineGlobalPtr() { return nullptr; }

} // namespace SteamKvInjector
