#include "PhylaxADUtils.h"
#include <windows.h>
#include <lm.h>
#pragma comment(lib, "Netapi32.lib")

bool IsUserInEnforcedGroup(PCWSTR username, const std::vector<std::wstring>& enforcedGroups) {
    LPBYTE pBuf = NULL;
    DWORD entriesRead = 0, totalEntries = 0;

    NET_API_STATUS nStatus = NetUserGetGroups(
        NULL,         // local server (NULL means use current)
        username,
        0,            // level 0: group names only
        &pBuf,
        MAX_PREFERRED_LENGTH,
        &entriesRead,
        &totalEntries
    );

    if (nStatus != NERR_Success || pBuf == NULL)
        return false;

    bool found = false;
    GROUP_USERS_INFO_0* pInfo = (GROUP_USERS_INFO_0*)pBuf;

    for (DWORD i = 0; i < entriesRead && !found; ++i) {
        std::wstring groupName = pInfo[i].grui0_name;
        for (const auto& enforced : enforcedGroups) {
            if (_wcsicmp(groupName.c_str(), enforced.c_str()) == 0) {
                found = true;
                break;
            }
        }
    }

    NetApiBufferFree(pBuf);
    return found;
}
