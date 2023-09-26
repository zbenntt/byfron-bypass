#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <Psapi.h>


void PrintPrivileges(HANDLE hToken) {
    DWORD dwLengthNeeded;
    if (!GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwLengthNeeded) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "Failed to retrieve token privileges. Error: " << GetLastError() << std::endl;
        return;
    }

    PTOKEN_PRIVILEGES tokenPrivileges = reinterpret_cast<PTOKEN_PRIVILEGES>(new BYTE[dwLengthNeeded]);

    if (!GetTokenInformation(hToken, TokenPrivileges, tokenPrivileges, dwLengthNeeded, &dwLengthNeeded)) {
        std::cerr << "Failed to retrieve token privileges. Error: " << GetLastError() << std::endl;
        delete[] tokenPrivileges;
        return;
    }

    std::cout << "Privileges after elevation:" << std::endl;
    for (DWORD i = 0; i < tokenPrivileges->PrivilegeCount; i++) {
        LUID_AND_ATTRIBUTES privilege = tokenPrivileges->Privileges[i];
        DWORD privilegeNameLength = 0;
        LookupPrivilegeName(NULL, &privilege.Luid, NULL, &privilegeNameLength);

        if (privilegeNameLength > 0) {
            std::vector<wchar_t> privilegeName(privilegeNameLength);
            if (LookupPrivilegeName(NULL, &privilege.Luid, privilegeName.data(), &privilegeNameLength)) {
                std::wcout << L"  " << privilegeName.data();
                if (privilege.Attributes & SE_PRIVILEGE_ENABLED) {
                    std::wcout << L" (Enabled)";
                }
                std::wcout << std::endl;

                // Check for specific privileges (e.g., read and write)
                if (wcscmp(privilegeName.data(), L"SeBackupPrivilege") == 0) {
                    std::wcout << L"    (This privilege allows backup access)" << std::endl;
                }
                if (wcscmp(privilegeName.data(), L"SeRestorePrivilege") == 0) {
                    std::wcout << L"    (This privilege allows restore access)" << std::endl;
                }
                // Add more checks for other privileges as needed
            }
        }
    }

    delete[] tokenPrivileges;
}


bool ElevateProcessPrivileges(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_CREATE_THREAD, FALSE, processId);

    if (hProcess == NULL) {
        std::cerr << "Failed to open the target process. Error: " << GetLastError() << std::endl;
        return false;
    }

    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "Failed to open process token. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // Enumerate all privileges and enable them
    DWORD dwLengthNeeded;
    if (!GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwLengthNeeded) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "Failed to retrieve token privileges. Error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return false;
    }

    PTOKEN_PRIVILEGES tokenPrivileges = reinterpret_cast<PTOKEN_PRIVILEGES>(new BYTE[dwLengthNeeded]);

    if (!GetTokenInformation(hToken, TokenPrivileges, tokenPrivileges, dwLengthNeeded, &dwLengthNeeded)) {
        std::cerr << "Failed to retrieve token privileges. Error: " << GetLastError() << std::endl;
        delete[] tokenPrivileges;
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return false;
    }

    for (DWORD i = 0; i < tokenPrivileges->PrivilegeCount; i++) {
        tokenPrivileges->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
    }

    if (!AdjustTokenPrivileges(hToken, FALSE, tokenPrivileges, 0, NULL, NULL)) {
        std::cerr << "Failed to adjust token privileges. Error: " << GetLastError() << std::endl;
        delete[] tokenPrivileges;
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return false;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        std::cerr << "Not all privileges were assigned." << std::endl;
        delete[] tokenPrivileges;
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return false;
    }

    // Obtain the process name
    TCHAR processName[MAX_PATH];
    if (GetProcessImageFileName(hProcess, processName, MAX_PATH) > 0) {
        std::wcout << L"The process name for the elevated thread is: " << processName << std::endl;
    }
    PrintPrivileges(hToken);
    delete[] tokenPrivileges;
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return true;
}

int main() {
    const wchar_t* targetProcessName = L"RobloxPlayerBeta.exe";
    DWORD targetProcessId = 0;
    // Find the RobloxPlayerBeta.exe process by name
    DWORD currentProcessId = GetCurrentProcessId();
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &processEntry)) {
            do {
                if (wcscmp(processEntry.szExeFile, targetProcessName) == 0) {
                    if (processEntry.th32ProcessID != currentProcessId) {
                        // Exclude the current process
                        targetProcessId = processEntry.th32ProcessID;
                        break;
                    }
                }
            } while (Process32Next(hSnapshot, &processEntry));
        }
        CloseHandle(hSnapshot);
    }

    if (targetProcessId == 0) {
        std::cerr << "Target process not found." << std::endl;
        return 1;
    }

    // Enumerate threads within the target process
    if (ElevateProcessPrivileges(targetProcessId)) {
        std::cout << "Privileges elevated successfully for process with ID " << targetProcessId << std::endl;
    }
    else {
        std::cerr << "Failed to elevate privileges for process with ID " << targetProcessId << std::endl;
    }

    // ...
    system("pause");

    return 0;
}
