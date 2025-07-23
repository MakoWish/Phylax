#include "PhylaxADUtils.h"
#include <lm.h>
#pragma comment(lib, "Netapi32.lib")

bool IsUserInGroup(PCWSTR username, PCWSTR groupName) {
    LPBYTE pBuf = nullptr;
    DWORD entriesRead = 0, totalEntries = 0;

    // Level 0 returns group names only (global/domain groups)
    NET_API_STATUS status = NetUserGetGroups(
        nullptr,        // local machine (DC)
        username,
        0,
        &pBuf,
        MAX_PREFERRED_LENGTH,
        &entriesRead,
        &totalEntries
    );

    if (status != NERR_Success || pBuf == nullptr) {
        if (pBuf) NetApiBufferFree(pBuf);
        return false;
    }

    GROUP_USERS_INFO_0* groups = reinterpret_cast<GROUP_USERS_INFO_0*>(pBuf);
    bool found = false;
    for (DWORD i = 0; i < entriesRead; ++i) {
        // Compare case-insensitive
        if (_wcsicmp(groups[i].grui0_name, groupName) == 0) {
            found = true;
            break;
        }
    }

    NetApiBufferFree(pBuf);
    return found;
}
