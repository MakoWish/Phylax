// PhylaxSettings.cpp
#include "PhylaxSettings.h"
#include <windows.h>
#include <shlwapi.h>
#include <algorithm>

#pragma comment(lib, "Shlwapi.lib")

#define PHYLAX_REG_PATH L"SOFTWARE\\Phylax"

PhylaxSettings::PhylaxSettings()
    : logSize(10240),
    logRetention(10),
    minimumLength(12),
    complexity(3),
    rejectSequences(true),
    rejectSequencesLength(3),
    rejectRepeats(true),
    rejectRepeatsLength(3),
    logLevel(LOGLEVEL_INFO) {
}


void PhylaxSettings::LoadFromRegistry() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, PHYLAX_REG_PATH, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        // Default values if key doesn't exist
        logPath = L"C:\\Windows\\System32";
        logName = L"phylax.log";
        logSize = 10240;
        logRetention = 10;
        minimumLength = 12;
        complexity = 3;
        rejectSequences = true;
        rejectSequencesLength = 3;
        rejectRepeats = true;
        rejectRepeatsLength = 3;
        blacklistPath = L"C:\\Windows\\System32\\phylax_blacklist.txt";
        badPatternsPath = L"C:\\Windows\\System32\\phylax_bad_patterns.txt";
        logLevel = LOGLEVEL_INFO;
    }
    else {
        WCHAR buffer[512]; DWORD len = sizeof(buffer);

        auto GetStr = [&](const wchar_t* name, std::wstring& target, const wchar_t* def) {
            len = sizeof(buffer);
            if (RegQueryValueExW(hKey, name, nullptr, nullptr, (LPBYTE)buffer, &len) == ERROR_SUCCESS)
                target = buffer;
            else
                target = def;
            };

        auto GetDWORD = [&](const wchar_t* name, DWORD& target, DWORD def) {
            DWORD val = 0; DWORD size = sizeof(DWORD);
            if (RegQueryValueExW(hKey, name, nullptr, nullptr, (LPBYTE)&val, &size) == ERROR_SUCCESS)
                target = val;
            else
                target = def;
            };

        auto GetBool = [&](const wchar_t* name, bool& target, bool def) {
            DWORD val = 0; DWORD size = sizeof(DWORD);
            if (RegQueryValueExW(hKey, name, nullptr, nullptr, (LPBYTE)&val, &size) == ERROR_SUCCESS)
                target = (val != 0);
            else
                target = def;
            };

        GetStr(L"LogPath", logPath, L"C:\\Windows\\System32");
        GetStr(L"LogName", logName, L"phylax.log");
        GetDWORD(L"LogSize", logSize, 10240);
        GetDWORD(L"LogRetention", logRetention, 10);
        GetDWORD(L"MinimumLength", minimumLength, 12);
        GetDWORD(L"Complexity", complexity, 3);
        GetBool(L"RejectSequences", rejectSequences, true);
        GetDWORD(L"RejectSequencesLength", rejectSequencesLength, 3);
        GetBool(L"RejectRepeats", rejectRepeats, true);
        GetDWORD(L"RejectRepeatsLength", rejectRepeatsLength, 3);
        GetStr(L"BlacklistFile", blacklistPath, L"C:\\Windows\\System32\\phylax_blacklist.txt");
        GetStr(L"BadPatternsFile", badPatternsPath, L"C:\\Windows\\System32\\phylax_bad_patterns.txt");

        // Read LogLevel as string
        std::wstring lvlStr;
        GetStr(L"LogLevel", lvlStr, L"INFO");
        std::transform(lvlStr.begin(), lvlStr.end(), lvlStr.begin(), ::towupper);

        if (lvlStr == L"DEBUG") logLevel = LOGLEVEL_DEBUG;
        else if (lvlStr == L"INFO") logLevel = LOGLEVEL_INFO;
        else if (lvlStr == L"WARN") logLevel = LOGLEVEL_WARN;
        else if (lvlStr == L"ERROR") logLevel = LOGLEVEL_ERROR;
        else logLevel = LOGLEVEL_INFO;

        RegCloseKey(hKey);
    }

    if (!logPath.empty() && logPath.back() != L'\\')
        logPath += L"\\";
    logFullPath = logPath + logName;
}
