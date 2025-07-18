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

void LogEvent(const std::wstring& message, DWORD level = LOGLEVEL_INFO) {
    if (level < g_settings.logLevel) return;

    CreateDirectoryW(g_settings.logPath.c_str(), NULL);
    std::wofstream logFile;
    logFile.open(g_settings.logFullPath, std::ios_base::app);
    if (logFile.is_open()) {
        SYSTEMTIME time;
        GetLocalTime(&time);
        logFile << L"[" << time.wYear << L"-" << time.wMonth << L"-" << time.wDay
            << L" " << time.wHour << L":" << time.wMinute << L":" << time.wSecond << L"] "
            << message << std::endl;
    }
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
    while (g_running) {
        {
            std::lock_guard<std::mutex> lock(g_settingsMutex);
            g_settings.LoadFromRegistry();
            LogEvent(L"[DEBUG] Settings loaded from registry.", LOGLEVEL_DEBUG);
        }
        LoadBlacklist(g_settings.blacklistPath);
        LoadBadPatterns(g_settings.badPatternsPath);
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
    std::wstring pwd(Password->Buffer, Password->Length / sizeof(WCHAR));
    std::wstring acct(AccountName->Buffer, AccountName->Length / sizeof(WCHAR));
    LogEvent(L"[DEBUG] PasswordFilter() called for account: " + acct, LOGLEVEL_DEBUG);

    {
        std::lock_guard<std::mutex> lock(g_settingsMutex);
        if (!PhylaxChecks::CheckPassword(pwd, g_settings, g_blacklist, g_badPatterns)) {
            LogEvent(L"[ERROR] Password rejected for account: " + acct, LOGLEVEL_ERROR);
            return FALSE;
        }
    }

    LogEvent(L"[INFO] Password accepted for account: " + acct, LOGLEVEL_INFO);
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
