// PhylaxChecks.cpp
#include "PhylaxChecks.h"
#include <cctype>
#include <algorithm>
#include <iterator>
#include <string>
#include <locale>
#include <unordered_set>

namespace PhylaxChecks {

    /*
    Basic check for password length
    Required password length is determined by registry settings
    */
    bool IsMinLength(const std::wstring& pwd, DWORD minLen) {
        return pwd.length() >= minLen;
    }

    /*
    Check to ensure the password contains the required number of character categories
    Number of required categories is determined by registry settings
    */
    bool HasRequiredComplexity(const std::wstring& pwd, DWORD requiredCategories) {
        bool hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
        for (wchar_t ch : pwd) {
            if (iswupper(ch)) hasUpper = true;
            else if (iswlower(ch)) hasLower = true;
            else if (iswdigit(ch)) hasDigit = true;
            else if (iswpunct(ch) || iswspace(ch)) hasSpecial = true;
        }
        int count = hasUpper + hasLower + hasDigit + hasSpecial;
        return count >= (int)requiredCategories;
    }

    /*
    Check for sequential characters (`1234`, `4321`, `abcd`, `dbca`)
    Number of characters in sequence is determinded by registry settings
    */
    bool HasSequential(const std::wstring& pwd, DWORD seqLen, std::wstring& seqOut) {
        if (seqLen < 2 || pwd.length() < seqLen) return false;
        for (size_t i = 0; i <= pwd.length() - seqLen; ++i) {
            bool ascending = true, descending = true;
            for (DWORD j = 0; j < seqLen - 1; ++j) {
                wchar_t curr = towlower(pwd[i + j]);
                wchar_t next = towlower(pwd[i + j + 1]);
                if (next != curr + 1) ascending = false;
                if (next != curr - 1) descending = false;
            }
            if (ascending || descending) {
                seqOut = pwd.substr(i, seqLen);
                return true;
            }
        }
        return false;
    }

    /*
    Check for repeated characters (`1111`, `AAAA`)
    Number of repeated characters is determinded by registry settings
    */
    bool HasRepeated(const std::wstring& pwd, DWORD repeatLen, std::wstring& seqOut) {
        if (repeatLen < 2 || pwd.length() < repeatLen) return false;
        size_t count = 1;
        for (size_t i = 1; i < pwd.length(); ++i) {
            if (pwd[i] == pwd[i - 1]) {
                count++;
                if (count >= repeatLen) {
                    seqOut = std::wstring(repeatLen, pwd[i]);
                    return true;
                }
            } else {
                count = 1;
            }
        }
        return false;
    }

    /*
    Check to see if the complete password has been blacklisted
    */
    bool IsBlacklisted(const std::wstring& pwd, const std::unordered_set<std::wstring>& blacklist) {
        std::wstring lower = pwd;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
        return blacklist.find(lower) != blacklist.end();
    }

    /*
    Check to see if the password contains a forbidden string
    */
    bool ContainsBadPattern(const std::wstring& pwd, const std::unordered_set<std::wstring>& patterns, std::wstring& patOut) {
        std::wstring lowerPwd = pwd;
        std::transform(lowerPwd.begin(), lowerPwd.end(), lowerPwd.begin(), towlower);
        for (const auto& pattern : patterns) {
            std::wstring lowerPattern = pattern;
            std::transform(lowerPattern.begin(), lowerPattern.end(), lowerPattern.begin(), towlower);
            if (lowerPwd.find(lowerPattern) != std::wstring::npos) {
                patOut = pattern;
                return true;
            }
        }
        return false;
    }

    /*
    CheckPassword()
    ---------------
    Main password policy check routine

    Parameters:
    pwd
        The plain-text password that is to be checked
    settings
        The current registry settings for Phylax password auditor
    blacklist
        The in-memory blacklisted passwords
    patterns
        The in-memory forbidden patterns/strings
    reason
        Variable to return the reason for rejection (if rejected)
    
    Return:
    true
        Password passed all checks
    false
        Password failed a check
    */
    bool CheckPassword(const std::wstring& pwd, const PhylaxSettings& settings,
                       const std::unordered_set<std::wstring>& blacklist,
                       const std::unordered_set<std::wstring>& patterns,
                       std::wstring& reject_reason) {
        if (pwd.length() < settings.minimumLength) {
            reject_reason = L"insufficient length";
            return false;
        }
        if (!HasRequiredComplexity(pwd, settings.complexity)) {
            reject_reason = L"insufficient complexity";
            return false;
        }
        if (settings.rejectSequences) {
            std::wstring seq;
            if (HasSequential(pwd, settings.rejectSequencesLength, seq)) {
                reject_reason = L"sequential pattern \"" + seq + L"\"";
                return false;
            }
        }
        if (settings.rejectRepeats) {
            std::wstring rpt;
            if (HasRepeated(pwd, settings.rejectRepeatsLength, rpt)) {
                reject_reason = L"repeated characters \"" + rpt + L"\"";
                return false;
            }
        }
        if (IsBlacklisted(pwd, blacklist)) {
            reject_reason = L"blacklisted/breached password";
            return false;
        }
        std::wstring pat;
        if (ContainsBadPattern(pwd, patterns, pat)) {
            reject_reason = L"forbidden string \"" + pat + L"\"";
            return false;
        }
        return true;
    }
} // namespace PhylaxChecks
