// PhylaxSettings.h
#pragma once

#include <string>
#include <Windows.h>
#include <vector>
#include <sstream>
#include <algorithm>

enum LogLevel {
    LOGLEVEL_DEBUG = 0,
    LOGLEVEL_INFO = 1,
    LOGLEVEL_WARN = 2,
    LOGLEVEL_ERROR = 3
};

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
    void CreateDefaultRegistrySettings();
};
