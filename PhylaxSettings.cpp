// PhylaxSettings.cpp
#include "PhylaxSettings.h"
#include <windows.h>
#include <shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

#define PHYLAX_REG_PATH L"SOFTWARE\\Phylax"

void PhylaxSettings::LoadFromRegistry() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, PHYLAX_REG_PATH, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        // Default values if key doesn't exist
        logPath = L"C:\\PhylaxLogs";
        logName = L"password_reject.log";
        logSize = 10240;
        logRetention = 10;
        minimumLength = 12;
        complexity = 3;
        rejectSequences = true;
        rejectSequencesLength = 3;
        rejectRepeats = true;
        rejectRepeatsLength = 3;
        blacklistPath = L"C:\\Phylax\\blacklist.txt";
        badPatternsPath = L"C:\\Phylax\\bad_patterns.txt";
    } else {
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

        GetStr(L"LogPath", logPath, L"C:\\PhylaxLogs");
        GetStr(L"LogName", logName, L"password_reject.log");
        GetDWORD(L"LogSize", logSize, 10240);
        GetDWORD(L"LogRetention", logRetention, 10);
        GetDWORD(L"MinimumLength", minimumLength, 12);
        GetDWORD(L"Complexity", complexity, 3);
        GetBool(L"RejectSequences", rejectSequences, true);
        GetDWORD(L"RejectSequencesLength", rejectSequencesLength, 3);
        GetBool(L"RejectRepeats", rejectRepeats, true);
        GetDWORD(L"RejectRepeatsLength", rejectRepeatsLength, 3);
        GetStr(L"BlacklistFile", blacklistPath, L"C:\\Phylax\\blacklist.txt");
        GetStr(L"BadPatternsFile", badPatternsPath, L"C:\\Phylax\\bad_patterns.txt");

        RegCloseKey(hKey);
    }

    if (!logPath.empty() && logPath.back() != L'\\')
        logPath += L"\\";
    logFullPath = logPath + logName;
}
