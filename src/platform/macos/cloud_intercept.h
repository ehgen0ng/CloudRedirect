#pragma once

#include "cloud_metadata_paths.h"
#include "common.h"

namespace CloudIntercept {

bool IsNamespaceApp(uint32_t appId);
bool HasNamespaceApps();
std::vector<uint32_t> GetNamespaceApps();
void AddNamespaceApp(uint32_t appId);
void RemoveNamespaceApp(uint32_t appId);
void SetNamespaceApps(const uint32_t* appIds, uint32_t count,
                      size_t* outAdded = nullptr, size_t* outRemoved = nullptr);

std::string GetSteamPath();
void SetSteamPath(const std::string& path);
uint32_t GetAccountId();
void SetAccountId(uint32_t accountId);
void Shutdown();

} // namespace CloudIntercept
