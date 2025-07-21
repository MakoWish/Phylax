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
#include <regex>
#include <shlwapi.h>
#include "PhylaxSettings.h"
#include "PhylaxChecks.h"
#include <algorithm>
#include "PhylaxADUtils.h"
#include "PhylaxGlobals.h"

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

// Helper to rotate logs with respect to LogSize and LogRetention
static void RotateLogIfNeeded() {
    std::error_code ec;
    std::wstring logFilePath = g_settings.logFullPath;

    // Check current log size
    if (!std::filesystem::exists(logFilePath, ec)) return;

    auto size = std::filesystem::file_size(logFilePath, ec);
    if (ec || size <= g_settings.logSize * 1024) return;  // logSize is in KB

    // Generate base and extension
    std::wstring basePath = logFilePath.substr(0, logFilePath.find_last_of(L'.'));
    std::wstring ext = logFilePath.substr(logFilePath.find_last_of(L'.'));

    // Delete/shift older rotated logs
    for (int i = g_settings.logRetention - 1; i >= 1; --i) {
        std::wstring oldName = basePath + L"." + std::to_wstring(i) + ext;
        std::wstring newName = basePath + L"." + std::to_wstring(i + 1) + ext;
        if (std::filesystem::exists(oldName, ec)) {
            std::filesystem::rename(oldName, newName, ec);
        }
    }

    // Move current log to .1
    std::wstring firstRotated = basePath + L".1" + ext;
    std::filesystem::rename(logFilePath, firstRotated, ec);
}

// Log helper
static void LogEvent(const std::wstring& message, DWORD level = LOGLEVEL_INFO) {
    if (level < g_settings.logLevel) return;

    EnterCriticalSection(&g_logLock);  //

    CreateDirectoryW(g_settings.logPath.c_str(), NULL);

    RotateLogIfNeeded();

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

    LeaveCriticalSection(&g_logLock);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        InitializeCriticalSection(&g_cs);
        InitializeCriticalSection(&g_logLock);
        g_settings.LoadFromRegistry();
    }
    else if (fdwReason == DLL_PROCESS_DETACH) {
        DeleteCriticalSection(&g_cs);
        DeleteCriticalSection(&g_logLock);
    }
    return TRUE;
}

static DWORD ComputeRegistrySettingsHash() {
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

static void LoadBlacklist(const std::wstring& path) {
    std::lock_guard<std::mutex> lock(g_settingsMutex);
    g_blacklist.clear();
    std::wifstream file(path);
    if (!file) {
        LogEvent(L"[WARN] Could not open blacklist file: " + path, LOGLEVEL_DEBUG);
        return;
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

static void LoadBadPatterns(const std::wstring& path) {
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

static void BackgroundWorker() {
    static fs::file_time_type lastBlacklistWriteTime;
    static fs::file_time_type lastBadPatternsWriteTime;

    while (g_running) {
        {
            std::lock_guard<std::mutex> lock(g_settingsMutex);
            DWORD currentHash = ComputeRegistrySettingsHash();
            if (currentHash != lastRegistryHash) {
                EnterCriticalSection(&g_cs);
                LogEvent(L"[INFO] Registry settings changes detected. Reloading...", LOGLEVEL_INFO);
                g_settings.LoadFromRegistry();
                std::wstringstream ss;
                ss << L"[DEBUG] Registry setting logPath: " << g_settings.logPath;
                LogEvent(ss.str(), LOGLEVEL_DEBUG); ss.str(L""); ss.clear();
                ss << L"[DEBUG] Registry setting logName: " << g_settings.logName;
                LogEvent(ss.str(), LOGLEVEL_DEBUG); ss.str(L""); ss.clear();
                ss << L"[DEBUG] Registry setting logSize: " << g_settings.logSize;
                LogEvent(ss.str(), LOGLEVEL_DEBUG); ss.str(L""); ss.clear();
                ss << L"[DEBUG] Registry setting logRetention: " << g_settings.logRetention;
                LogEvent(ss.str(), LOGLEVEL_DEBUG); ss.str(L""); ss.clear();
                ss << L"[DEBUG] Registry setting minimumLength: " << g_settings.minimumLength;
                LogEvent(ss.str(), LOGLEVEL_DEBUG); ss.str(L""); ss.clear();
                ss << L"[DEBUG] Registry setting complexity: " << g_settings.complexity;
                LogEvent(ss.str(), LOGLEVEL_DEBUG); ss.str(L""); ss.clear();
                ss << L"[DEBUG] Registry setting rejectSequences: " << g_settings.rejectSequences;
                LogEvent(ss.str(), LOGLEVEL_DEBUG); ss.str(L""); ss.clear();
                ss << L"[DEBUG] Registry setting rejectSequencesLength: " << g_settings.rejectSequencesLength;
                LogEvent(ss.str(), LOGLEVEL_DEBUG); ss.str(L""); ss.clear();
                ss << L"[DEBUG] Registry setting rejectRepeats: " << g_settings.rejectRepeats;
                LogEvent(ss.str(), LOGLEVEL_DEBUG); ss.str(L""); ss.clear();
                ss << L"[DEBUG] Registry setting rejectRepeatsLength: " << g_settings.rejectRepeatsLength;
                LogEvent(ss.str(), LOGLEVEL_DEBUG); ss.str(L""); ss.clear();
                ss << L"[DEBUG] Registry setting blacklistPath: " << g_settings.blacklistPath;
                LogEvent(ss.str(), LOGLEVEL_DEBUG); ss.str(L""); ss.clear();
                ss << L"[DEBUG] Registry setting badPatternsPath: " << g_settings.badPatternsPath;
                LogEvent(ss.str(), LOGLEVEL_DEBUG); ss.str(L""); ss.clear();
                LeaveCriticalSection(&g_cs);
                lastRegistryHash = currentHash;
            }
        }

        // Check if blacklist has changed
        if (fs::exists(g_settings.blacklistPath)) {
            auto newTime = fs::last_write_time(g_settings.blacklistPath);
            if (newTime != lastBlacklistWriteTime) {
                LogEvent(L"[INFO] Blacklist file changes detected. Reloading...", LOGLEVEL_INFO);
                LoadBlacklist(g_settings.blacklistPath);
                lastBlacklistWriteTime = newTime;
            }
        }

        // Check if bad patterns file has changed
        if (fs::exists(g_settings.badPatternsPath)) {
            auto newTime = fs::last_write_time(g_settings.badPatternsPath);
            if (newTime != lastBadPatternsWriteTime) {
                LogEvent(L"[INFO] Bad patterns file changes detected. Reloading...", LOGLEVEL_INFO);
                LoadBadPatterns(g_settings.badPatternsPath);
                lastBadPatternsWriteTime = newTime;
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
}

extern "C" __declspec(dllexport) BOOL WINAPI InitializeChangeNotify(void) {
    static std::thread worker(BackgroundWorker);
    worker.detach();
    return TRUE;
}

extern "C" __declspec(dllexport) BOOL WINAPI PasswordChangeNotify(
    PUNICODE_STRING UserName,
    ULONG RelativeId,
    PUNICODE_STRING NewPassword
) {
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

    // Static cache to suppress duplicate log entries from pre-check and commit calls by LSASS
    static std::mutex logMutex;
    static std::wstring lastAcct;
    static std::wstring lastReason;
    static ULONGLONG lastTimestamp = 0;

    // LogEvent(L"[DEBUG] PasswordFilter() called for account: " + acct, LOGLEVEL_DEBUG);

    // Group check logic here
    if (!g_settings.enforcedGroups.empty()) {
        if (!IsUserInEnforcedGroup(acct.c_str(), g_settings.enforcedGroups)) {
            LogEvent(L"[DEBUG] User '" + acct + L"' is not in an enforced group, skipping password checks.", LOGLEVEL_DEBUG);
            LeaveCriticalSection(&g_cs);
            return TRUE;
        }
        else {
            ULONGLONG now = GetTickCount64();
            std::lock_guard<std::mutex> lock(logMutex);
            if (acct != lastAcct || (now - lastTimestamp) > 1000) {
                LogEvent(L"[DEBUG] User '" + acct + L"' is in an enforced group, enforcing password checks.", LOGLEVEL_DEBUG);
                lastAcct = acct;
                lastTimestamp = now;
            }
        }
    }

    std::wstring reason;
    bool result;

    {
        std::lock_guard<std::mutex> lock(g_settingsMutex);
        result = PhylaxChecks::CheckPassword(pwd, g_settings, g_blacklist, g_badPatterns, reason);
    }

    if (!result) {
        ULONGLONG now = GetTickCount64();
        std::lock_guard<std::mutex> lock(logMutex);
        if (acct != lastAcct || reason != lastReason || (now - lastTimestamp) > 1000) {
            LogEvent(L"[WARN] Password rejected due to " + reason + L" for account: " + acct, LOGLEVEL_WARN);
            lastAcct = acct;
            lastReason = reason;
            lastTimestamp = now;
        }
        return FALSE;
    }

    LogEvent(L"[INFO] Password accepted for account: " + acct, LOGLEVEL_INFO);
    return TRUE;
}
