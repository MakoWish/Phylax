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
#include <algorithm>
#include "PhylaxSettings.h"
#include "PhylaxChecks.h"
#include "PhylaxADUtils.h"
#pragma comment(lib, "Shlwapi.lib")
typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)


// Globals
namespace fs = std::filesystem;
std::mutex g_settingsMutex;
std::thread g_worker;
std::atomic_bool g_running(true);
std::unordered_set<std::wstring> g_blacklist;
std::unordered_set<std::wstring> g_badPatterns;
LARGE_INTEGER gPerformanceFrequency;
CRITICAL_SECTION g_logLock;
PhylaxSettings g_settings;
DWORD lastRegistryHash = 0;

/*
DLLMain entry point
Keep It Simple, Stupid (KISS)
*/
BOOL WINAPI DllMain(_In_ HINSTANCE hinstDLL, _In_ DWORD fdwReason, _In_ LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Disable needless thread notifications
        DisableThreadLibraryCalls(hinstDLL);

        // CRITICAL_SECTION inits only
        InitializeCriticalSection(&g_logLock);
    }
    else if (fdwReason == DLL_PROCESS_DETACH) {
        // Kill our background watcher task
        g_running = false;
        if (g_worker.joinable())
            g_worker.join();

        // Remove CRITICAL_SECTION
        DeleteCriticalSection(&g_logLock);
    }
    return true;
}

// Helper to rotate logs with respect to LogSize and LogRetention settings
void RotateLogIfNeeded() {
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
        std::wstring oldName = basePath + ext + L"." + std::to_wstring(i);
        std::wstring newName = basePath + ext + L"." + std::to_wstring(i + 1);
        if (std::filesystem::exists(oldName, ec)) {
            std::filesystem::rename(oldName, newName, ec);
        }
    }

    // Move current log to .1
    std::wstring firstRotated = basePath + ext + L".1";
    std::filesystem::rename(logFilePath, firstRotated, ec);
}

/*
Log helper
*/
void LogEvent(const std::wstring& message, DWORD level = LOGLEVEL_INFO) {
    if (level < g_settings.logLevel) return;

    EnterCriticalSection(&g_logLock);

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

// Helper to append vector of strings to a stream, separated by comma
std::wstring JoinGroupVector(const std::vector<std::wstring>& groups) {
    std::wstring result;
    for (const auto& group : groups) {
        if (!result.empty()) result += L",";
        result += group;
    }
    return result;
}

/*
Compute a hash from registry settings to detect changes
*/
static DWORD ComputeRegistrySettingsHash() {
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

/*
Helper to load blacklisted passwords from file
*/
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

/*
Helper to load forbidden patterns/strings from file
*/
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
Background worker to check for and load changes from registry settings, blacklist file, and bad patterns file.
*/
static void BackgroundWorker() {
    static fs::file_time_type lastBlacklistWriteTime;
    static fs::file_time_type lastBadPatternsWriteTime;

    while (g_running) {
        {
            std::lock_guard<std::mutex> lock(g_settingsMutex);
            DWORD currentHash = ComputeRegistrySettingsHash();
            if (currentHash != lastRegistryHash) {
                if (lastRegistryHash == 0) {
                    LogEvent(L"[INFO] Phylax password policy is starting...", LOGLEVEL_INFO);
                    LogEvent(L"[INFO] Loading Phylax settings from registry...", LOGLEVEL_INFO);
                }
                else {
                    LogEvent(L"[INFO] Registry settings changes detected. Reloading...", LOGLEVEL_INFO);
                }
                g_settings.LoadFromRegistry();

                // Convert groups to CSV for logging
                std::wstring groupsCSV;
                for (size_t i = 0; i < g_settings.enforcedGroups.size(); ++i) {
                    groupsCSV += g_settings.enforcedGroups[i];
                    if (i + 1 < g_settings.enforcedGroups.size())
                        groupsCSV += L",";
                }
                std::wstring adminGroupsCSV;
                for (size_t i = 0; i < g_settings.adminGroups.size(); ++i) {
                    adminGroupsCSV += g_settings.adminGroups[i];
                    if (i + 1 < g_settings.adminGroups.size())
                        adminGroupsCSV += L",";
                }
                std::wstring serviceGroupsCSV;
                for (size_t i = 0; i < g_settings.serviceGroups.size(); ++i) {
                    serviceGroupsCSV += g_settings.serviceGroups[i];
                    if (i + 1 < g_settings.serviceGroups.size())
                        serviceGroupsCSV += L",";
                }

                LogEvent(L"[INFO] Registry setting LogPath: " + g_settings.logPath, LOGLEVEL_INFO);
                LogEvent(L"[INFO] Registry setting LogName: " + g_settings.logName, LOGLEVEL_INFO);
                LogEvent(L"[INFO] Registry setting LogSize: " + std::to_wstring(g_settings.logSize), LOGLEVEL_INFO);
                LogEvent(L"[INFO] Registry setting LogRetention: " + std::to_wstring(g_settings.logRetention), LOGLEVEL_INFO);
                LogEvent(L"[INFO] Registry setting EnforcedGroups: " + groupsCSV, LOGLEVEL_INFO);
                LogEvent(L"[INFO] Registry setting MinimumLength: " + std::to_wstring(g_settings.minimumLength), LOGLEVEL_INFO);
                LogEvent(L"[INFO] Registry setting AdminGroups: " + adminGroupsCSV, LOGLEVEL_INFO);
                LogEvent(L"[INFO] Registry setting AdminMinLength: " + std::to_wstring(g_settings.adminMinLength), LOGLEVEL_INFO);
                LogEvent(L"[INFO] Registry setting ServiceAccountGroups: " + serviceGroupsCSV, LOGLEVEL_INFO);
                LogEvent(L"[INFO] Registry setting ServiceMinLength: " + std::to_wstring(g_settings.serviceMinLength), LOGLEVEL_INFO);
                LogEvent(L"[INFO] Registry setting Complexity: " + std::to_wstring(g_settings.complexity), LOGLEVEL_INFO);
                LogEvent(L"[INFO] Registry setting RejectSequences: " + std::to_wstring(g_settings.rejectSequences), LOGLEVEL_INFO);
                LogEvent(L"[INFO] Registry setting RejectSequencesLength: " + std::to_wstring(g_settings.rejectSequencesLength), LOGLEVEL_INFO);
                LogEvent(L"[INFO] Registry setting RejectRepeats: " + std::to_wstring(g_settings.rejectRepeats), LOGLEVEL_INFO);
                LogEvent(L"[INFO] Registry setting RejectRepeatsLength: " + std::to_wstring(g_settings.rejectRepeatsLength), LOGLEVEL_INFO);
                LogEvent(L"[INFO] Registry setting BlacklistPath: " + g_settings.blacklistPath, LOGLEVEL_INFO);
                LogEvent(L"[INFO] Registry setting BadPatternsPath: " + g_settings.badPatternsPath, LOGLEVEL_INFO);
                lastRegistryHash = currentHash;
            }
        }

        // Check if blacklist file has changed
        if (fs::exists(g_settings.blacklistPath)) {
            auto newTime = fs::last_write_time(g_settings.blacklistPath);
            if (lastBlacklistWriteTime == fs::file_time_type{}) {
                // first time ever
                LogEvent(L"[INFO] Loading blacklist file: " + g_settings.blacklistPath, LOGLEVEL_INFO);
                LoadBlacklist(g_settings.blacklistPath);
            }
            else if (newTime != lastBlacklistWriteTime) {
                // subsequent reload
                LogEvent(L"[INFO] Blacklist file change detected. Reloading...", LOGLEVEL_INFO);
                LoadBlacklist(g_settings.blacklistPath);
            }
            lastBlacklistWriteTime = newTime;
        }

        // Check if bad patterns file has changed
        if (fs::exists(g_settings.badPatternsPath)) {
            auto newTime = fs::last_write_time(g_settings.badPatternsPath);
            if (lastBadPatternsWriteTime == fs::file_time_type{}) {
                LogEvent(L"[INFO] Loading bad patterns file: " + g_settings.badPatternsPath, LOGLEVEL_INFO);
                LoadBadPatterns(g_settings.badPatternsPath);
            }
            else if (newTime != lastBadPatternsWriteTime) {
                LogEvent(L"[INFO] Bad patterns file change detected. Reloading...", LOGLEVEL_INFO);
                LoadBadPatterns(g_settings.badPatternsPath);
            }
            lastBadPatternsWriteTime = newTime;
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
    // Start background worker for detection of changes
    // This will load the initial settings and watch for changes
    try {
        if (!g_worker.joinable()) {
            g_running = true;
            g_worker = std::thread(BackgroundWorker);
        }
    }
    catch (...) {
        // Failing to load the worker means settings will not load. Bail out!
        OutputDebugStringW(L"ERROR: Failed to create background worker thread!\n");
        return FALSE;
    }

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
    return STATUS_SUCCESS;
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
    _In_ PUNICODE_STRING AccountName,
    _In_ PUNICODE_STRING FullName,
    _In_ PUNICODE_STRING Password,
    _In_ BOOLEAN SetOperation
) {
    std::wstring acct(AccountName->Buffer, AccountName->Length / sizeof(WCHAR));
    std::wstring full(FullName->Buffer, FullName->Length / sizeof(WCHAR));
    std::wstring pwd(Password->Buffer, Password->Length / sizeof(WCHAR));

    // --- DE-DUPLICATION BY PASSWORD BUFFER POINTER ---
    // LSASS calls the policy twice on a rejection. Try and deduplicate
    // the rejection log events.
    static thread_local void* lastPwdBuffer = nullptr;
    bool shouldLog = (lastPwdBuffer != (void*)Password->Buffer);
    if (shouldLog) {
        lastPwdBuffer = (void*)Password->Buffer;
    }
    // Ensure next invocation resets the pointer
    struct ClearLast {
        ~ClearLast() { lastPwdBuffer = nullptr; }
    } clearOnExit;


    // Start a timer to calculate processing time
    auto start = std::chrono::steady_clock::now();

    // Always allow password changes for the krbtgt or RODC krbtgt accounts
    if (acct == L"krbtgt" || acct.rfind(L"krbtgt_", 0) == 0)
    {
        LogEvent(L"[DEBUG] Always allowing password change for krbtgt account '" + acct + L"'.", LOGLEVEL_DEBUG);
        if (!pwd.empty()) {
            // Zero out the pwd variable to prevent plain-text passwords from remaining in memory
            SecureZeroMemory(&pwd[0], pwd.size() * sizeof(wchar_t));
            pwd.clear();
            pwd.shrink_to_fit();
        }
        return true;
    }

    // Log the start of SET or CHANGE attempt
    if (SetOperation) {
        LogEvent(L"[DEBUG] Attempting to SET password for user '" + acct + L"'.", LOGLEVEL_DEBUG);
    }
    else {
        LogEvent(L"[DEBUG] Attempting to CHANGE password for user '" + acct + L"'.", LOGLEVEL_DEBUG);
    }

    // Default to minimum length from registry settings
    DWORD effectiveMinLen = g_settings.minimumLength;

    // Admins group minimum length override
    for (auto& grp : g_settings.adminGroups) {
        if (IsUserInGroup(acct.c_str(), grp.c_str())) {
            effectiveMinLen = g_settings.adminMinLength;
            LogEvent(L"[INFO] User '" + acct + L"' (" + full + L") is a member of enforced admins group '" + grp.c_str() + L"'. Enforcing password checks.", LOGLEVEL_INFO);
            goto gotMinLen;
        }
    }

    // Service accounts group minimum override
    for (auto& grp : g_settings.serviceGroups) {
        if (IsUserInGroup(acct.c_str(), grp.c_str())) {
            LogEvent(L"[INFO] User '" + acct + L"' (" + full + L") is a member of enforced service accounts group '" + grp.c_str() + L"'. Enforcing password checks.", LOGLEVEL_INFO);
            effectiveMinLen = g_settings.serviceMinLength;
            goto gotMinLen;
        }
    }

    // Default/EnforcedGroups minimum password length
    if (!g_settings.enforcedGroups.empty()) {
        std::wstring matchedGroup;
        bool inGroup = false;
        for (const auto& grp : g_settings.enforcedGroups) {
            if (IsUserInGroup(acct.c_str(), grp.c_str())) {
                matchedGroup = grp;
                inGroup = true;
                break;
            }
        }

        if (!inGroup) {
            LogEvent(L"[INFO] User '" + acct + L"' (" + full + L") is not a member of any enforced groups. Skipping password checks.", LOGLEVEL_INFO);
            if (!pwd.empty()) {
                // Zero out the pwd variable to prevent plain-text passwords from remaining in memory
                SecureZeroMemory(&pwd[0], pwd.size() * sizeof(wchar_t));
                pwd.clear();
                pwd.shrink_to_fit();
            }
            return true;
        }
        else {
            LogEvent(L"[INFO] User '" + acct + L"' (" + full + L") is a member of enforced group '" + matchedGroup.c_str() + L"'. Enforcing password checks.", LOGLEVEL_INFO);
        }
    }

    // Jump here once password length requirement acquired based on group membership
    gotMinLen:;

    // First, enforce minimum length
    if (pwd.length() < effectiveMinLen) {
        auto end = std::chrono::steady_clock::now();
        double elapsedMs = std::chrono::duration<double, std::milli>(end - start).count();
        double durationMs = std::round(elapsedMs * 1e5) / 1e5;

        LogEvent(L"[WARN] Password rejected after " + std::to_wstring(durationMs) + L"ms due to insufficient length for account: " + acct, LOGLEVEL_WARN);
        if (!pwd.empty()) {
            // Zero out the pwd variable to prevent plain-text passwords from remaining in memory
            SecureZeroMemory(&pwd[0], pwd.size() * sizeof(wchar_t));
            pwd.clear();
            pwd.shrink_to_fit();
        }
        return FALSE;
    }

    std::wstring reject_reason;
    bool is_accepted;

    {
        std::lock_guard<std::mutex> lock(g_settingsMutex);
        is_accepted = PhylaxChecks::CheckPassword(pwd, g_settings, g_blacklist, g_badPatterns, reject_reason);
    }

    auto end = std::chrono::steady_clock::now();
    double elapsedMs = std::chrono::duration<double, std::milli>(end - start).count();
    double durationMs = std::round(elapsedMs * 1e5) / 1e5;

    // Zero out the pwd variable to prevent plain-text passwords from remaining in memory
    if (!pwd.empty()) {
        SecureZeroMemory(&pwd[0], pwd.size() * sizeof(wchar_t));
        pwd.clear();
        pwd.shrink_to_fit();
    }

    if (is_accepted) {
        LogEvent(L"[INFO] Password accepted after " + std::to_wstring(durationMs) + L"ms for account: " + acct, LOGLEVEL_INFO);
        return true;
    }
    else {
        LogEvent(L"[WARN] Password rejected after " + std::to_wstring(durationMs) + L"ms due to " + reject_reason + L" for account: " + acct, LOGLEVEL_WARN);
        return false;
    }

}
