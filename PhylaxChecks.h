// PhylaxChecks.h
#pragma once

#include <string>
#include <unordered_set>
#include "PhylaxSettings.h"
#include <Windows.h>

// External declaration to use LogLevel within PhylaxChecks.cpp
extern void LogEvent(const std::wstring& message, DWORD level);

namespace PhylaxChecks {

bool CheckPassword(const std::wstring& pwd, const PhylaxSettings& settings,
    const std::unordered_set<std::wstring>& blacklist,
    const std::unordered_set<std::wstring>& patterns,
    std::wstring& reason);


} // namespace PhylaxChecks
