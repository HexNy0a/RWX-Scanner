#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#pragma comment (lib,"Psapi.lib")

int processScanTotal = 0; // 扫描的进程的数量
HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

void PrintProcess(HANDLE hProcess, PROCESSENTRY32 p32, bool printPath) {
    if (!printPath) {
        for (int i = 0; i < MAX_PATH; i++) {
            printf("%s", &p32.szExeFile[i]); // 输出进程名
        }
        printf("\n");
    }
    else {
        char exePath[MAX_PATH];
        if (GetModuleFileNameExA(hProcess, NULL, exePath, MAX_PATH)) {
            printf("%s\n", &exePath); // 输出进程路径
        }
        else {
            printf(" 无法获取进程路径\n");
        }
    }
}

void RWX_Scan(PROCESSENTRY32 p32) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, p32.th32ProcessID); // 获取进程全部权限的句柄

    if (hProcess != NULL) {
        MEMORY_BASIC_INFORMATION mbi; // 存储内存信息的结构体
        LPCVOID lpAddress = NULL;

        while (VirtualQueryEx(hProcess, lpAddress, &mbi, sizeof(mbi))) { // 遍历内存
            if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_EXECUTE_READWRITE)) { // RWX
                SetConsoleTextAttribute(hConsole, 0xF + 4 * 0x10);
                printf("存在RWX: ");
                PrintProcess(hProcess, p32, TRUE);
                return;
            }
            lpAddress = (PBYTE)mbi.BaseAddress + mbi.RegionSize; // 当前内存块地址 + 当前内存块大小
        }
    }
    else {
        SetConsoleTextAttribute(hConsole, 3 * 0x10);
        printf("无法打开进程: ");
        PrintProcess(hProcess, p32, FALSE);
    }
}

void EnableDebugPrivilege() {
    HANDLE hToken;
    // 打开当前进程令牌，指定 TOKEN_ADJUST_PRIVILEGES 以修改令牌特权
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        TOKEN_PRIVILEGES tp; // 用于存储令牌特权信息的结构体
        tp.PrivilegeCount = 1; // 特权数量为1
        LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid); // 指定启用的特权，SE_DEBUG_NAME 对应 SeDebugPrivilege特权
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; // SE_PRIVILEGE_ENABLED 表示启用特权
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL); // 将令牌特权信息应用到令牌上
    }
}

void ProcessScan() {
    EnableDebugPrivilege(); // 获取 SeDebugPrivilege特权

    HANDLE lpSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // 创建所有进程快照

    PROCESSENTRY32 p32 = { 0 }; // 存储进程快照的结构体
    p32.dwSize = sizeof(PROCESSENTRY32); // 设置结构体正确大小，这样才能填充全部进程信息
    Process32First(lpSnapshot, &p32); // 将全部进程信息写入p32

    do {
        RWX_Scan(p32); // 扫描进程内存
        processScanTotal++;
    } while (Process32Next(lpSnapshot, &p32)); // 遍历每一个进程

    SetConsoleTextAttribute(hConsole, 0xF * 0x10);
    printf("扫描的进程数量: %d", processScanTotal);
}

int main() {
    ProcessScan(); // 扫描每一个进程
    getchar();
}