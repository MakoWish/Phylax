// PhylaxPasswordFilter.cpp
// Main DLL implementation for Active Directory Password Filter

#include <windows.h>
#include <ntsecapi.h>
#include <string>
#include <thread>
#include <mutex>
#include <vector>
#include <unordered_set>
#include <fstream>
#include <sstream>
#include <chrono>
#include <atomic>
#include <shlwapi.h>
#include "PhylaxSettings.h"
#include "PhylaxChecks.h"

#pragma comment(lib, "Shlwapi.lib")

// Globals
std::mutex g_settingsMutex;
std::atomic_bool g_running(true);
PhylaxSettings g_settings;
std::unordered_set<std::wstring> g_blacklist;
std::unordered_set<std::wstring> g_badPatterns;

void LogEvent(const std::wstring& message);

void LoadBlacklist(const std::wstring& path) {
    std::lock_guard<std::mutex> lock(g_settingsMutex);
    g_blacklist.clear();
    std::wifstream file(path);
    if (!file) return;
    std::wstring line;
    while (std::getline(file, line)) {
        g_blacklist.insert(line);
    }
}

void LoadBadPatterns(const std::wstring& path) {
    std::lock_guard<std::mutex> lock(g_settingsMutex);
    g_badPatterns.clear();
    std::wifstream file(path);
    if (!file) return;
    std::wstring line;
    while (std::getline(file, line)) {
        g_badPatterns.insert(line);
    }
}

void BackgroundWorker() {
    while (g_running) {
        {
            std::lock_guard<std::mutex> lock(g_settingsMutex);
            g_settings.LoadFromRegistry();
        }
        LoadBlacklist(g_settings.blacklistPath);
        LoadBadPatterns(g_settings.badPatternsPath);
        std::this_thread::sleep_for(std::chrono::minutes(5));
    }
}

extern "C" BOOL WINAPI InitializeChangeNotify(void) {
    static std::thread worker(BackgroundWorker);
    worker.detach();
    return TRUE;
}

extern "C" BOOL WINAPI PasswordChangeNotify(
    PUNICODE_STRING UserName,
    ULONG RelativeId,
    PUNICODE_STRING NewPassword
) {
    return TRUE;
}

extern "C" BOOLEAN WINAPI PasswordFilter(
    PUNICODE_STRING AccountName,
    PUNICODE_STRING FullName,
    PUNICODE_STRING Password,
    BOOLEAN SetOperation
) {
    std::wstring pwd(Password->Buffer, Password->Length / sizeof(WCHAR));
    {
        std::lock_guard<std::mutex> lock(g_settingsMutex);
        if (!PhylaxChecks::CheckPassword(pwd, g_settings, g_blacklist, g_badPatterns)) {
            LogEvent(L"Password rejected for account: " + std::wstring(AccountName->Buffer, AccountName->Length / sizeof(WCHAR)));
            return FALSE;
        }
    }
    return TRUE;
}

void LogEvent(const std::wstring& message) {
    std::wofstream logFile;
    logFile.open(g_settings.logFullPath, std::ios_base::app);
    if (logFile.is_open()) {
        SYSTEMTIME time;
        GetLocalTime(&time);
        logFile << L"[" << time.wYear << L"-" << time.wMonth << L"-" << time.wDay
                << L" " << time.wHour << L":" << time.wMinute << L":" << time.wSecond << L"] " << message << std::endl;
    }
}
