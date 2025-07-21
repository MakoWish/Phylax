#pragma once
#include <windows.h>
#include <string>
#include <vector>

bool IsUserInEnforcedGroup(PCWSTR username, const std::vector<std::wstring>& enforcedGroups);
