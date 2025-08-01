// PhylaxSettings.cpp
#include "PhylaxSettings.h"
#include <windows.h>
#include <shlwapi.h>
#include <algorithm>
#include <fstream>
#include <filesystem>

#pragma comment(lib, "Shlwapi.lib")

#define PHYLAX_REG_PATH L"SOFTWARE\\Phylax"

// Define default settings in case of registry load issues
PhylaxSettings::PhylaxSettings() :
    logSize(10240),
    logRetention(10),
    minimumLength(12),
    adminMinLength(15),
    serviceMinLength(20),
    complexity(3),
    rejectSequences(true),
    rejectSequencesLength(3),
    rejectRepeats(true),
    rejectRepeatsLength(3),
    logLevel(LOGLEVEL_INFO) {
}

// Helper to split CSV into vector<wstring>
auto parseCsv = [&](const std::wstring& raw) {
    std::vector<std::wstring> out;
    std::wstringstream ss(raw);
    std::wstring item;
    while (std::getline(ss, item, L',')) {
        // trim whitespace…
        item.erase(0, item.find_first_not_of(L" \t\r\n"));
        item.erase(item.find_last_not_of(L" \t\r\n") + 1);
        if (!item.empty()) out.push_back(item);
    }
    return out;
};

// Helper to split vector<wstring> into CSV
std::wstring JoinGroupVector(const std::vector<std::wstring>& groups) {
    std::wstring result;
    for (const auto& group : groups) {
        if (!result.empty()) result += L",";
        result += group;
    }
    return result;
}

// Helper to create default registry settings
bool PhylaxSettings::CreateDefaultSettings() {
    HKEY hKey;
    DWORD disposition;

    if (RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        PHYLAX_REG_PATH,
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE | KEY_QUERY_VALUE,
        nullptr,
        &hKey,
        &disposition) == ERROR_SUCCESS) {

        struct StringDefault {
            const wchar_t* name;
            const wchar_t* value;
        };

        struct DWORDDefault {
            const wchar_t* name;
            DWORD value;
        };

        StringDefault stringDefaults[] = {
            {L"LogPath", L"C:\\Windows\\System32"},
            {L"LogName", L"phylax.log"},
            {L"BlacklistFile", L"C:\\Windows\\System32\\phylax_blacklist.txt"},
            {L"BadPatternsFile", L"C:\\Windows\\System32\\phylax_bad_patterns.txt"},
            {L"LogLevel", L"INFO"},
            {L"EnforcedGroups", L""},
            {L"AdminGroups", L""},
            {L"ServiceAccountGroups", L""}
        };

        DWORDDefault dwordDefaults[] = {
            {L"LogSize", 10240},
            {L"LogRetention", 10},
            {L"MinimumLength", 12},
            {L"AdminMinLength", 15},
            {L"ServiceMinLength", 20},
            {L"Complexity", 3},
            {L"RejectSequences", 1},
            {L"RejectSequencesLength", 3},
            {L"RejectRepeats", 1},
            {L"RejectRepeatsLength", 3}
        };

        // Set string values if they do not exist
        for (const auto& def : stringDefaults) {
            DWORD type = 0;
            DWORD size = 0;
            if (RegQueryValueExW(hKey, def.name, nullptr, &type, nullptr, &size) != ERROR_SUCCESS) {
                RegSetValueExW(hKey, def.name, 0, REG_SZ,
                    (const BYTE*)def.value,
                    static_cast<DWORD>((wcslen(def.value) + 1) * sizeof(wchar_t)));
            }
        }

        // Set DWORD values if they do not exist
        for (const auto& def : dwordDefaults) {
            DWORD type = 0;
            DWORD size = sizeof(DWORD);
            if (RegQueryValueExW(hKey, def.name, nullptr, &type, nullptr, &size) != ERROR_SUCCESS) {
                RegSetValueExW(hKey, def.name, 0, REG_DWORD, (const BYTE*)&def.value, sizeof(DWORD));
            }
        }

        RegCloseKey(hKey);
    }
    else {
        LogEvent(L"[ERROR] Failed to create default registry settings.", LOGLEVEL_ERROR);
        return false;
    }

    bool success = true;

    // Ensure blacklist and bad patterns files exist
    //std::wofstream blacklistOut(blacklistPath, std::ios::app);
    //if (!blacklistOut.is_open()) {
        //LogEvent(L"[ERROR] Failed to open or create blacklist file: " + blacklistPath, LOGLEVEL_ERROR);
        //success = false;
    //} else {
        //blacklistOut << L"############################################################\n";
        //blacklistOut << L"# List of fobidden patterns, strings, etc.to not be found\n";
        //blacklistOut << L"# in any part of a password.These include company - related\n";
        //blacklistOut << L"# words / names, proper names, dates, years, seasons, sports,\n";
        //blacklistOut << L"# common \"swipe\" patterns observed in passwords, etc.\n";
        //blacklistOut << L"############################################################\n";
        //blacklistOut.close();
    //}

    //std::wofstream patternsOut(badPatternsPath, std::ios::app);
    //if (!patternsOut.is_open()) {
        //LogEvent(L"[ERROR] Failed to open or create bad-patterns file: " + badPatternsPath, LOGLEVEL_ERROR);
        //success = false;
    //} else {
        //patternsOut << L"############################################################\n";
        //patternsOut << L"# List of breached or cracked passwords.These are exact\n";
        //patternsOut << L"# matches (case-insensitive) that are to be disallowed\n";
        //patternsOut << L"# due to being breached, cracked during audits, etc.\n";
        //patternsOut << L"############################################################\n";
        //patternsOut.close();
    //}

    return success;
}

// Helper to load blacklisted passwords from file
void LoadBlacklist(const std::wstring& path) {
    std::lock_guard<std::mutex> lock(g_settingsMutex);
    g_blacklist.clear();

    std::wifstream file(path);
    if (!file) {
        // File missing or unreadable - create it
        LogEvent(L"[WARN] Blacklist not found, creating default: " + path, LOGLEVEL_WARN);
        std::wofstream create(path, std::ios::out);
        if (!create) {
            LogEvent(L"[ERROR] Failed to create blacklist file: " + path, LOGLEVEL_ERROR);
            return;
        }
        create
            << L"############################################################\n"
            << L"# List of breached or cracked passwords. These are exact\n"
            << L"# matches (case-insensitive) that are to be disallowed\n"
            << L"# due to being breached, cracked on internal audits, etc.\n"
            << L"############################################################\n";
        create.close();

        // Re - try read
        file.open(path);
        if (!file) {
            LogEvent(L"[ERROR] Still cannot open blacklist after create: " + path, LOGLEVEL_ERROR);
            return;
        }
    }
    std::wstring line;
    while (std::getline(file, line)) {
        // Trim whitespace (optional but recommended)
        line.erase(0, line.find_first_not_of(L" \t\r\n"));
        line.erase(line.find_last_not_of(L" \t\r\n") + 1);

        // Convert to lowercase
        std::transform(line.begin(), line.end(), line.begin(), ::towlower);

        if (!line.empty()) {
            g_blacklist.insert(line);
        }
    }
    LogEvent(L"[INFO] Blacklist loaded. Entries: " + std::to_wstring(g_blacklist.size()), LOGLEVEL_INFO);
}

// Helper to load forbidden patterns/strings from file
void LoadBadPatterns(const std::wstring& path) {
    std::lock_guard<std::mutex> lock(g_settingsMutex);
    g_badPatterns.clear();

    std::wifstream file(path);
    if (!file) {
        // File missing or unreadable - create it
        LogEvent(L"[WARN] Bad-patterns file not found, creating default: " + path, LOGLEVEL_WARN);
        std::wofstream create(path, std::ios::out);
        if (!create) {
            LogEvent(L"[ERROR] Failed to create bad-patterns file: " + path, LOGLEVEL_ERROR);
            return;
        }
        create
            << L"############################################################\n"
            << L"# List of fobidden patterns, strings, etc. to not be found\n"
            << L"# in any part of a password. These include company - related\n"
            << L"# words / names, proper names, dates, years, seasons, sports,\n"
            << L"# common \"swipe\" patterns observed in passwords, etc.\n"
            << L"############################################################\n";
        create.close();

        // 2b) Re-try read
        file.open(path);
        if (!file) {
            LogEvent(L"[ERROR] Still cannot open bad-patterns after create: " + path, LOGLEVEL_ERROR);
            return;
        }
    }
    std::wstring line;
    while (std::getline(file, line)) {
        // Trim whitespace (optional but recommended)
        line.erase(0, line.find_first_not_of(L" \t\r\n"));
        line.erase(line.find_last_not_of(L" \t\r\n") + 1);

        // Convert to lowercase
        std::transform(line.begin(), line.end(), line.begin(), ::towlower);

        if (!line.empty()) {
            g_badPatterns.insert(line);
        }
    }
    LogEvent(L"[INFO] Bad patterns loaded. Entries: " + std::to_wstring(g_badPatterns.size()), LOGLEVEL_INFO);
}

/*
Helper to load string from registry
*/
std::wstring ReadStringSetting(HKEY hKey, const std::wstring& name, const std::wstring& defaultValue) {
    WCHAR buffer[1024];
    DWORD size = sizeof(buffer);
    if (RegQueryValueExW(hKey, name.c_str(), nullptr, nullptr, (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
        return std::wstring(buffer);
    }
    return defaultValue;
}

/*
Load registry settings
*/
void PhylaxSettings::LoadFromRegistry() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, PHYLAX_REG_PATH, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        // Default values if key doesn't exist
        CreateDefaultSettings();
        LogEvent(L"[WARN] Registry settings not found. Creating defaults...", LOGLEVEL_WARN);
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
        GetDWORD(L"AdminMinLength", adminMinLength, 15);
        GetDWORD(L"ServiceMinLength", serviceMinLength, 20);
        GetDWORD(L"Complexity", complexity, 3);
        GetBool(L"RejectSequences", rejectSequences, true);
        GetDWORD(L"RejectSequencesLength", rejectSequencesLength, 3);
        GetBool(L"RejectRepeats", rejectRepeats, true);
        GetDWORD(L"RejectRepeatsLength", rejectRepeatsLength, 3);
        GetStr(L"BlacklistFile", blacklistPath, L"C:\\Windows\\System32\\phylax_blacklist.txt");
        GetStr(L"BadPatternsFile", badPatternsPath, L"C:\\Windows\\System32\\phylax_bad_patterns.txt");

        std::wstring groupsRaw = ReadStringSetting(hKey, L"EnforcedGroups", L"");
        std::wstringstream ss(groupsRaw);
        std::wstring group;
        enforcedGroups.clear();
        while (std::getline(ss, group, L',')) {
            group.erase(0, group.find_first_not_of(L""));
            group.erase(group.find_last_not_of(L"") + 1);
            if (!group.empty()) enforcedGroups.push_back(group);
        }

        // Get admin groups from registry
        std::wstring rawAdmins;
        GetStr(L"AdminGroups", rawAdmins, L"");
        adminGroups = parseCsv(rawAdmins);
        GetDWORD(L"AdminMinLength", adminMinLength, minimumLength);

        // Get service account groups from registry
        std::wstring rawServices;
        GetStr(L"ServiceAccountGroups", rawServices, L"");
        serviceGroups = parseCsv(rawServices);
        GetDWORD(L"ServiceMinLength", serviceMinLength, minimumLength);

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

/*
Compute a hash from registry settings to detect changes
*/
DWORD ComputeRegistrySettingsHash() {
    PhylaxSettings tempSettings;
    tempSettings.LoadFromRegistry();

    std::wstringstream ss;
    ss << tempSettings.logPath
        << tempSettings.logName
        << tempSettings.logSize
        << tempSettings.logRetention
        << JoinGroupVector(tempSettings.enforcedGroups)
        << tempSettings.minimumLength
        << JoinGroupVector(tempSettings.adminGroups)
        << tempSettings.adminMinLength
        << JoinGroupVector(tempSettings.serviceGroups)
        << tempSettings.serviceMinLength
        << tempSettings.complexity
        << tempSettings.rejectSequences
        << tempSettings.rejectSequencesLength
        << tempSettings.rejectRepeats
        << tempSettings.rejectRepeatsLength
        << tempSettings.blacklistPath
        << tempSettings.badPatternsPath
        << tempSettings.logLevel;

    for (const auto& group : tempSettings.enforcedGroups)
        ss << group;

    std::wstring settingsStr = ss.str();
    DWORD hash = 0;
    for (wchar_t ch : settingsStr)
        hash = (hash * 131) + ch;  // simple rolling hash

    return hash;
}
