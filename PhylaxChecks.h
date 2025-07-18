// PhylaxChecks.h
#pragma once

#include <string>
#include <unordered_set>
#include "PhylaxSettings.h"
#include <Windows.h>

namespace PhylaxChecks {

bool CheckPassword(const std::wstring& pwd, const PhylaxSettings& settings,
    const std::unordered_set<std::wstring>& blacklist,
    const std::unordered_set<std::wstring>& patterns,
    std::wstring& reason);


} // namespace PhylaxChecks
