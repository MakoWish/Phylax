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

// DLLMain entry point
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

/*
Background worker to check for and load changes from blocklist file, bad patterns file, and registry settings.
This function has no parameters.
This function has no return.
*/
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

/*
InitializeChangeNotify()
------------------------
InitializeChangeNotify is called by the Local Security Authority (LSA) to verify that the password notification DLL is loaded and initialized.
This function must use the __stdcall calling convention, and must be exported by the DLL.
This function is called only for password filters that are installed and registered on a system.
Any process exception that is not handled within this function may cause security-related failures system-wide. Structured exception handling should be used when appropriate.

This callback function has no parameters.

Return code 	Description
TRUE
    The password filter DLL is initialized.
FALSE
    The password filter DLL is not initialized.
*/
extern "C" __declspec(dllexport) BOOL WINAPI InitializeChangeNotify(void) {
    static std::thread worker(BackgroundWorker);
    worker.detach();
    return TRUE;
}

/*
PasswordChangeNotify()
----------------------
The PasswordChangeNotify function is called after the PasswordFilter function has been called successfully and the new password has been stored.

Parameters:
UserName [in]
    The account name of the user whose password changed.
    If the values of this parameter and the NewPassword parameter are NULL, this function should return STATUS_SUCCESS.
RelativeId [in]
    The relative identifier (RID) of the user specified in UserName.
NewPassword [in]
    A new plaintext password for the user specified in UserName. When you have finished using the password, clear the
    information by calling the SecureZeroMemory function. For more information about protecting passwords, see Handling Passwords.
    If the values of this parameter and the UserName parameter are NULL, this function should return STATUS_SUCCESS.

Return code 	Description
STATUS_SUCCESS
    Indicates the password of the user was changed, or that the values of both the UserName and NewPassword parameters are NULL.

This function must use the __stdcall calling convention and must be exported by the DLL.
When the PasswordChangeNotify routine is running, processing is blocked until the routine is finished. When appropriate, 
move any lengthy processing to a separate thread prior to returning from this routine.
This function is called only for password filters that are installed and registered on the system.
Any process exception that is not handled within this function may cause security-related failures system-wide. 
Structured exception handling should be used when appropriate.
*/
extern "C" __declspec(dllexport) BOOL WINAPI PasswordChangeNotify(
    PUNICODE_STRING UserName,
    ULONG RelativeId,
    PUNICODE_STRING NewPassword
) {
    return TRUE;
}

/*
PasswordFilter()
----------------
The PasswordFilter function is implemented by a password filter DLL. The value returned by this 
function determines whether the new password is accepted by the system. All of the password filters 
installed on a system must return TRUE for the password change to take effect.

Parameters:
[in] AccountName
    Pointer to a UNICODE_STRING that represents the name of the user whose password changed.
[in] FullName
    Pointer to a UNICODE_STRING that represents the full name of the user whose password changed.
[in] Password
    Pointer to a UNICODE_STRING that represents the new plaintext password. When you have finished 
    using the password, clear it from memory by calling the SecureZeroMemory function. For more 
    information on protecting the password, see Handling Passwords.
[in] SetOperation
    TRUE if the password was set rather than changed.

Return code 	Description
TRUE
    Return TRUE if the new password is valid with respect to the password policy implemented in the 
    password filter DLL. When TRUE is returned, the Local Security Authority (LSA) continues to evaluate 
    the password by calling any other password filters installed on the system.
FALSE
    Return FALSE if the new password is not valid with respect to the password policy implemented in 
    the password filter DLL. When FALSE is returned, the LSA returns the ERROR_ILL_FORMED_PASSWORD 
    (1324) status code to the source of the password change request.

This function must use the __stdcall calling convention and must be exported by the DLL.

When the PasswordFilter routine is running, processing is blocked until the routine is finished. When 
appropriate, move any lengthy processing to a separate thread prior to returning from this routine.

This function is called only for password filters that are installed and registered on a system.

Any process exception that is not handled within this function may cause security-related failures system-wide. 
Structured exception handling should be used when appropriate.
*/
extern "C" __declspec(dllexport) BOOLEAN WINAPI PasswordFilter(
    PUNICODE_STRING AccountName,
    PUNICODE_STRING FullName,
    PUNICODE_STRING Password,
    BOOLEAN SetOperation
) {
    std::wstring acct(AccountName->Buffer, AccountName->Length / sizeof(WCHAR));
    std::wstring pwd(Password->Buffer, Password->Length / sizeof(WCHAR));

    // Always allow password changes for the krbtgt account
    if (wcscmp(AccountName, L"krbtgt") == 0)
    {
        LogMessageW(
            LOG_DEBUG,
            L"[%s:%s@%d] Always allowing password change for krbtgt account.",
            __FILENAMEW__,
            __FUNCTIONW__,
            __LINE__);
        return TRUE;
    }

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
