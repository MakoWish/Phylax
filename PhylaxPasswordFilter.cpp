// PhylaxPasswordFilter.cpp
// Main DLL implementation for Active Directory Password Filter

#include <windows.h>
#include <mutex>
#include <iomanip>
#include <ntsecapi.h>
#include <string>
#include <thread>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <chrono>
#include <atomic>
#include <shlwapi.h>
#include "PhylaxSettings.h"
#include "PhylaxChecks.h"
#include <algorithm>
#include "PhylaxADUtils.h"

#pragma comment(lib, "Shlwapi.lib")

// Globals
namespace fs = std::filesystem;
std::mutex g_settingsMutex;
std::atomic_bool g_running(true);
std::unordered_set<std::wstring> g_blacklist;
std::unordered_set<std::wstring> g_badPatterns;
PhylaxSettings g_settings;
CRITICAL_SECTION g_cs;
DWORD lastRegistryHash = 0;

void LogEvent(const std::wstring& message, DWORD level = LOGLEVEL_INFO) {
    if (level < g_settings.logLevel) return;

    CreateDirectoryW(g_settings.logPath.c_str(), NULL);
    std::wofstream logFile;
    logFile.open(g_settings.logFullPath, std::ios_base::app);
    if (logFile.is_open()) {
        SYSTEMTIME time;
        GetLocalTime(&time);
        logFile << L"[" << time.wYear << L"-"
            << std::setw(2) << std::setfill(L'0') << time.wMonth << L"-"
            << std::setw(2) << std::setfill(L'0') << time.wDay << L" "
            << std::setw(2) << std::setfill(L'0') << time.wHour << L":"
            << std::setw(2) << std::setfill(L'0') << time.wMinute << L":"
            << std::setw(2) << std::setfill(L'0') << time.wSecond << L"] "
            << message << std::endl;
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        InitializeCriticalSection(&g_cs);
        g_settings.LoadFromRegistry();
    }
    else if (fdwReason == DLL_PROCESS_DETACH) {
        DeleteCriticalSection(&g_cs);
    }
    return TRUE;
}

DWORD ComputeRegistrySettingsHash() {
    PhylaxSettings tempSettings;
    tempSettings.LoadFromRegistry();

    std::wstringstream ss;
    ss << tempSettings.logPath
        << tempSettings.logName
        << tempSettings.logSize
        << tempSettings.logRetention
        << tempSettings.minimumLength
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

void LoadBlacklist(const std::wstring& path) {
    std::lock_guard<std::mutex> lock(g_settingsMutex);
    g_blacklist.clear();
    std::wifstream file(path);
    if (!file) {
        LogEvent(L"[WARN] Could not open blacklist file: " + path, LOGLEVEL_DEBUG);
        return;
    }
    std::wstring line;
    while (std::getline(file, line)) {
        g_blacklist.insert(line);
    }
    LogEvent(L"[INFO] Blacklist loaded. Entries: " + std::to_wstring(g_blacklist.size()), LOGLEVEL_INFO);
}

void LoadBadPatterns(const std::wstring& path) {
    std::lock_guard<std::mutex> lock(g_settingsMutex);
    g_badPatterns.clear();
    std::wifstream file(path);
    if (!file) {
        LogEvent(L"[WARN] Could not open bad patterns file: " + path, LOGLEVEL_WARN);
        return;
    }
    std::wstring line;
    while (std::getline(file, line)) {
        g_badPatterns.insert(line);
    }
    LogEvent(L"[INFO] Bad patterns loaded. Entries: " + std::to_wstring(g_badPatterns.size()), LOGLEVEL_INFO);
}

void BackgroundWorker() {
    static fs::file_time_type lastBlacklistWriteTime;
    static fs::file_time_type lastBadPatternsWriteTime;

    while (g_running) {
        {
            std::lock_guard<std::mutex> lock(g_settingsMutex);
            DWORD currentHash = ComputeRegistrySettingsHash();
            if (currentHash != lastRegistryHash) {
                EnterCriticalSection(&g_cs);
                g_settings.LoadFromRegistry();
                LeaveCriticalSection(&g_cs);
                LogEvent(L"[INFO] Registry settings reloaded due to detected change.", LOGLEVEL_INFO);
                lastRegistryHash = currentHash;
            }
        }

        // Check if blacklist has changed
        if (fs::exists(g_settings.blacklistPath)) {
            auto newTime = fs::last_write_time(g_settings.blacklistPath);
            if (newTime != lastBlacklistWriteTime) {
                LogEvent(L"[INFO] Detected change in blacklist file, reloading.", LOGLEVEL_INFO);
                LoadBlacklist(g_settings.blacklistPath);
                lastBlacklistWriteTime = newTime;
            }
        }

        // Check if bad patterns file has changed
        if (fs::exists(g_settings.badPatternsPath)) {
            auto newTime = fs::last_write_time(g_settings.badPatternsPath);
            if (newTime != lastBadPatternsWriteTime) {
                LogEvent(L"[INFO] Detected change in bad patterns file, reloading.", LOGLEVEL_INFO);
                LoadBadPatterns(g_settings.badPatternsPath);
                lastBadPatternsWriteTime = newTime;
            }
        }
        std::this_thread::sleep_for(std::chrono::minutes(5));
    }
}

extern "C" __declspec(dllexport) BOOL WINAPI InitializeChangeNotify(void) {
    static std::thread worker(BackgroundWorker);
    worker.detach();
    LogEvent(L"[DEBUG] InitializeChangeNotify() called - Phylax DLL loaded.", LOGLEVEL_DEBUG);
    return TRUE;
}

extern "C" __declspec(dllexport) BOOL WINAPI PasswordChangeNotify(
    PUNICODE_STRING UserName,
    ULONG RelativeId,
    PUNICODE_STRING NewPassword
) {
    LogEvent(L"[DEBUG] PasswordChangeNotify() called.", LOGLEVEL_DEBUG);
    return TRUE;
}

extern "C" __declspec(dllexport) BOOLEAN WINAPI PasswordFilter(
    PUNICODE_STRING AccountName,
    PUNICODE_STRING FullName,
    PUNICODE_STRING Password,
    BOOLEAN SetOperation
) {
    std::wstring acct(AccountName->Buffer, AccountName->Length / sizeof(WCHAR));
    std::wstring pwd(Password->Buffer, Password->Length / sizeof(WCHAR));

    // LogEvent(L"[DEBUG] PasswordFilter() called for account: " + acct, LOGLEVEL_DEBUG);

    // Group check logic here
    if (!g_settings.enforcedGroups.empty()) {
        if (!IsUserInEnforcedGroup(acct.c_str(), g_settings.enforcedGroups)) {
            LogEvent(L"[DEBUG] User '" + acct + L"' is not in an enforced group, skipping password checks.", LOGLEVEL_DEBUG);
            LeaveCriticalSection(&g_cs);
            return TRUE;
        }
        else {
            LogEvent(L"[DEBUG] User '" + acct + L"' is in an enforced group, enforcing password checks.", LOGLEVEL_DEBUG);
        }
    }

    std::wstring reason;
    bool result;

    {
        std::lock_guard<std::mutex> lock(g_settingsMutex);
        result = PhylaxChecks::CheckPassword(pwd, g_settings, g_blacklist, g_badPatterns, reason);
    }

    // Static cache to suppress duplicate log entries
    static std::mutex logMutex;
    static std::wstring lastAcct;
    static std::wstring lastReason;
    static ULONGLONG lastTimestamp = 0;

    if (!result) {
        ULONGLONG now = GetTickCount64();
        std::lock_guard<std::mutex> lock(logMutex);
        if (acct != lastAcct || reason != lastReason || (now - lastTimestamp) > 1000) {
            LogEvent(L"[ERROR] Password rejected due to " + reason + L" for account: " + acct, LOGLEVEL_ERROR);
            lastAcct = acct;
            lastReason = reason;
            lastTimestamp = now;
        }
        return FALSE;
    }

    LogEvent(L"[INFO] Password accepted for account: " + acct, LOGLEVEL_INFO);
    return TRUE;
}

