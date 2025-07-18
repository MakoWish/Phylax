// PhylaxSettings.h
#pragma once

#include <string>

class PhylaxSettings {
public:
    std::wstring logPath;
    std::wstring logName;
    DWORD logSize;
    DWORD logRetention;
    DWORD minimumLength;
    DWORD complexity;
    bool rejectSequences;
    DWORD rejectSequencesLength;
    bool rejectRepeats;
    DWORD rejectRepeatsLength;
    std::wstring blacklistPath;
    std::wstring badPatternsPath;
    std::wstring logFullPath;

    void LoadFromRegistry();
};
