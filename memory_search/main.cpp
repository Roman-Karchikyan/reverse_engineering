#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>


void searchMemoryInProcess(uint32_t processId, uint32_t valueToFind) {
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (hProcess == NULL) {
        std::cerr << "Failed to open process. Error code: " << GetLastError() << std::endl;
        return;
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    uintptr_t minAddress = reinterpret_cast<uintptr_t>(sysInfo.lpMinimumApplicationAddress);
    uintptr_t maxAddress = reinterpret_cast<uintptr_t>(sysInfo.lpMaximumApplicationAddress);

    MEMORY_BASIC_INFORMATION memInfo;
    for (uintptr_t address = minAddress; address < maxAddress; address += memInfo.RegionSize) {
        if (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(address), &memInfo, sizeof(memInfo)) == 0) {
            std::cerr << "VirtualQueryEx failed. Error code: " << GetLastError() << std::endl;
            break;
        }
        if (memInfo.State == MEM_COMMIT && (memInfo.Protect & (PAGE_READWRITE | PAGE_WRITECOPY)) != 0) {
            std::vector<std::byte> buffer(memInfo.RegionSize);
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(address), buffer.data(), memInfo.RegionSize, &bytesRead) != 0) {
                for (size_t i = 0; i < bytesRead / sizeof(uint32_t); ++i) {
                    if (*reinterpret_cast<uint32_t*>(&buffer[i * sizeof(uint32_t)]) == valueToFind) {
                        std::cout << "Value found at address: " << std::hex << address + i * sizeof(uint32_t) << std::endl;
                        CloseHandle(hProcess); // Close handle before returning
                        return; // Terminate search after finding the first occurrence
                    }
                }
            } else {
                DWORD lastError = GetLastError();
                if (lastError != ERROR_PARTIAL_COPY) {
                    std::cerr << "ReadProcessMemory failed. Error code: " << lastError << std::endl;
                    std::cerr << "Failed address: " << std::hex << address << std::endl;
                    std::cerr << "Region size: " << memInfo.RegionSize << std::endl;
                }
            }
        }
    }

    CloseHandle(hProcess);
}


DWORD findProcessIdByName(const std::wstring& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(hSnapshot, &entry)) {
        CloseHandle(hSnapshot);
        return 0;
    }

    do {
        if (wcscmp(entry.szExeFile, processName.c_str()) == 0) {
            CloseHandle(hSnapshot);
            return entry.th32ProcessID;
        }
    } while (Process32NextW(hSnapshot, &entry));

    CloseHandle(hSnapshot);
    return 0;
}

int main() {
    std::wstring processName = L"Telegram.exe";
    DWORD processId = findProcessIdByName(processName);
    if (processId == 0) {
        std::cerr << "Failed to find process: " << std::string(processName.begin(), processName.end()) << std::endl;
        return 1;
    }

    std::cout << "Found process: " << std::string(processName.begin(), processName.end()) << ", Process ID: " << processId << std::endl;

    uint32_t valueToFind = 0x24242424;
    searchMemoryInProcess(processId, valueToFind);

    return 0;
}
