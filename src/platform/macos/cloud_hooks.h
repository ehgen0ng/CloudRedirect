#pragma once

#include <cstddef>
#include <cstdint>

namespace MacCloudHooks {

bool ResolveProtobufHelpers(uintptr_t textStart, size_t textSize);
void SetOriginals(void* slot5, void* slot7, void* slot8);
void BeginShutdown();

} // namespace MacCloudHooks
