// PhylaxChecks.cpp
#include "PhylaxChecks.h"
#include <cctype>
#include <algorithm>
#include <iterator>
#include <string>
#include <unordered_set>

namespace PhylaxChecks {

bool IsMinLength(const std::wstring& pwd, DWORD minLen) {
    return pwd.length() >= minLen;
}

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

bool HasSequential(const std::wstring& pwd, DWORD seqLen) {
    if (seqLen < 2 || pwd.length() < seqLen) return false;
    for (size_t i = 0; i <= pwd.length() - seqLen; ++i) {
        bool ascending = true, descending = true;
        for (DWORD j = 0; j < seqLen - 1; ++j) {
            wchar_t curr = towlower(pwd[i + j]);
            wchar_t next = towlower(pwd[i + j + 1]);
            if (next != curr + 1) ascending = false;
            if (next != curr - 1) descending = false;
        }
        if (ascending || descending) return true;
    }
    return false;
}

bool HasRepeated(const std::wstring& pwd, DWORD repeatLen) {
    if (repeatLen < 2 || pwd.length() < repeatLen) return false;
    size_t count = 1;
    for (size_t i = 1; i < pwd.length(); ++i) {
        if (pwd[i] == pwd[i - 1]) {
            count++;
            if (count >= repeatLen) return true;
        } else {
            count = 1;
        }
    }
    return false;
}

bool IsBlacklisted(const std::wstring& pwd, const std::unordered_set<std::wstring>& blacklist) {
    return blacklist.find(pwd) != blacklist.end();
}

bool ContainsBadPattern(const std::wstring& pwd, const std::unordered_set<std::wstring>& patterns) {
    std::wstring lowerPwd = pwd;
    std::transform(lowerPwd.begin(), lowerPwd.end(), lowerPwd.begin(), towlower);
    for (const auto& pattern : patterns) {
        std::wstring lowerPattern = pattern;
        std::transform(lowerPattern.begin(), lowerPattern.end(), lowerPattern.begin(), towlower);
        if (lowerPwd.find(lowerPattern) != std::wstring::npos) {
            return true;
        }
    }
    return false;
}

bool CheckPassword(const std::wstring& pwd, const PhylaxSettings& settings,
                   const std::unordered_set<std::wstring>& blacklist,
                   const std::unordered_set<std::wstring>& patterns) {

    if (!IsMinLength(pwd, settings.minimumLength)) return false;
    if (!HasRequiredComplexity(pwd, settings.complexity)) return false;
    if (settings.rejectSequences && HasSequential(pwd, settings.rejectSequencesLength)) return false;
    if (settings.rejectRepeats && HasRepeated(pwd, settings.rejectRepeatsLength)) return false;
    if (IsBlacklisted(pwd, blacklist)) return false;
    if (ContainsBadPattern(pwd, patterns)) return false;
    return true;
}

} // namespace PhylaxChecks
