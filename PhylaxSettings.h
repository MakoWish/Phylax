// PhylaxSettings.h
#pragma once

#include <string>
#include <Windows.h>
#include <vector>
#include <sstream>
#include <algorithm>
#include <mutex>
#include <unordered_set>
#include <unordered_map>

void LoadBlacklist(const std::wstring& path);
void LoadBadPatterns(const std::wstring& path);

extern std::mutex g_settingsMutex;
extern std::unordered_set<std::wstring> g_blacklist;
extern std::unordered_set<std::wstring> g_badPatterns;

enum LogLevel {
    LOGLEVEL_DEBUG = 0,
    LOGLEVEL_INFO = 1,
    LOGLEVEL_WARN = 2,
    LOGLEVEL_ERROR = 3
};

// External declaration to use LogLevel within PhylaxSettings.cpp
extern void LogEvent(const std::wstring& message, DWORD level);

class PhylaxSettings {
public:
    std::vector<std::wstring> enforcedGroups;
    std::vector<std::wstring> adminGroups;
    std::vector<std::wstring> serviceGroups;
    std::wstring logPath;
    std::wstring logName;
    DWORD logSize;
    DWORD logRetention;
    DWORD minimumLength;
    DWORD adminMinLength;
    DWORD serviceMinLength;
    DWORD complexity;
    bool rejectSequences;
    DWORD rejectSequencesLength;
    bool rejectRepeats;
    DWORD rejectRepeatsLength;
    std::wstring blacklistPath;
    std::wstring badPatternsPath;
    std::wstring logFullPath;
    DWORD logLevel;

    PhylaxSettings();
    void LoadFromRegistry();
    // Returns true on success, false if critical files can't be created
    bool CreateDefaultSettings();
};

// Helper to join a vector of wstrings into a comma-separated wstring
std::wstring JoinGroupVector(const std::vector<std::wstring>& groups);

// Compute a rolling hash of current registry-based settings to detect changes
DWORD ComputeRegistrySettingsHash();