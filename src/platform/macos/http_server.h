#pragma once
// macOS blob HTTP server using POSIX sockets and per-process URL authentication.

#include <cstdint>
#include <string>
#include <vector>

namespace HttpServer {

bool Start(const std::string& blobRoot, uint32_t accountId = 0);
void SetAccountId(uint32_t accountId);
void SetMaxUploadMB(int mb);
void Stop();
uint16_t GetPort();

// Append the capability token required by the macOS loopback server.
std::string AddAuthToken(const std::string& path);

bool HasBlob(uint32_t accountId, uint32_t appId, const std::string& filename);
uint64_t GetBlobSize(uint32_t accountId, uint32_t appId, const std::string& filename);
std::vector<uint8_t> ReadBlob(uint32_t accountId, uint32_t appId, const std::string& filename);
bool DeleteBlob(uint32_t accountId, uint32_t appId, const std::string& filename);

} // namespace HttpServer
