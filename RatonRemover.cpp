#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <taskschd.h>
#include <comdef.h>
#include <stdio.h>
#include <string>
#include <vector>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

#define COLOR_RED     12
#define COLOR_GREEN   10
#define COLOR_YELLOW  14
#define COLOR_CYAN    11
#define COLOR_WHITE   15

struct Signature {
    const BYTE* bytes;
    DWORD       length;
    const char* name;
    int         tier;      
};

struct Detection {
    std::wstring path;
    std::string  matchName;
    DWORD        pid;
    std::wstring processName;
    std::string  sha256;
    int          type;     
    std::wstring regKey;
    std::wstring regValue;
    HKEY         regHive;
    std::wstring taskName;
};
static const BYTE SIG_RATON_SALT[] = { 'R',0,'A',0,'T',0,'O',0,'N',0,'_',0,'S',0,'A',0,'L',0,'T',0 };
static const BYTE SIG_123RATONPRO[] = { '1',0,'2',0,'3',0,'r',0,'a',0,'t',0,'o',0,'n',0,'p',0,'r',0,'o',0 };
static const BYTE SIG_BOTKILLER[] = { '.',0,'B',0,'o',0,'t',0,'K',0,'i',0,'l',0,'l',0,'e',0,'r',0,'R',0,'a',0,'t',0,'o',0,'n',0 };
static const BYTE SIG_SILLYCLIENT[] = { 'S',0,'i',0,'l',0,'l',0,'y',0,'C',0,'l',0,'i',0,'e',0,'n',0,'t',0 };
static const BYTE SIG_CLIENTRATON[] = { 'C',0,'l',0,'i',0,'e',0,'n',0,'t',0,'.',0,'R',0,'a',0,'t',0,'o',0,'n',0 };
static const BYTE SIG_PLATFORMRT[] = { 'P',0,'l',0,'a',0,'t',0,'f',0,'o',0,'r',0,'m',0,'R',0,'u',0,'n',0,'t',0,'i',0,'m',0,'e',0 };
static const BYTE SIG_CLIENTFORCRYPT[] = { 'c',0,'l',0,'i',0,'e',0,'n',0,'t',0,'F',0,'o',0,'r',0,'C',0,'r',0,'y',0,'p',0,'t',0,'e',0,'r',0,'s',0 };
static const BYTE SIG_COSTURASTUFF[] = { 'c',0,'o',0,'s',0,'t',0,'u',0,'r',0,'a',0,'.',0,'s',0,'t',0,'u',0,'f',0,'f',0,'.',0,'d',0,'l',0,'l',0 };
static const BYTE SIG_RATON_UID[] = { 'R',0,'a',0,'t',0,'o',0,'n',0,'_',0 };
static const BYTE SIG_DEADBEEF[] = { 0xEF, 0xBE, 0xAD, 0xDE };
static const BYTE SIG_LISTINFO[] = { 'l',0,'i',0,'s',0,'t',0,'i',0,'n',0,'f',0,'o',0 };

static Signature signatures[] = {
    { SIG_RATON_SALT,      sizeof(SIG_RATON_SALT),      "RATON_SALT",         1 },
    { SIG_123RATONPRO,     sizeof(SIG_123RATONPRO),     "123ratonpro",        1 },
    { SIG_BOTKILLER,       sizeof(SIG_BOTKILLER),       ".BotKillerRaton",    1 },
    { SIG_SILLYCLIENT,     sizeof(SIG_SILLYCLIENT),     "SillyClient",        2 },
    { SIG_CLIENTRATON,     sizeof(SIG_CLIENTRATON),      "Client.Raton",       2 },
    { SIG_PLATFORMRT,      sizeof(SIG_PLATFORMRT),       "PlatformRuntime",    2 },
    { SIG_CLIENTFORCRYPT,  sizeof(SIG_CLIENTFORCRYPT),   "clientForCrypters",  2 },
    { SIG_COSTURASTUFF,    sizeof(SIG_COSTURASTUFF),     "costura.stuff.dll",  2 },
    { SIG_RATON_UID,       sizeof(SIG_RATON_UID),        "Raton_",             2 },
    { SIG_DEADBEEF,        sizeof(SIG_DEADBEEF),         "0xDEADBEEF",         2 },
    { SIG_LISTINFO,        sizeof(SIG_LISTINFO),         "listinfo",           2 },
};

static std::vector<Detection> detections;
static HANDLE hConsole;
static DWORD ownPid;
static WCHAR ownPath[MAX_PATH * 2];

void SetColor(int color) {
    SetConsoleTextAttribute(hConsole, color);
}

void PrintColored(int color, const char* fmt, ...) {
    SetColor(color);
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    SetColor(COLOR_WHITE);
}

BOOL IsAdmin() {
    BOOL admin = FALSE;
    HANDLE token = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elev;
        DWORD size;
        if (GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &size))
            admin = elev.TokenIsElevated;
        CloseHandle(token);
    }
    return admin;
}

BOOL EnableDebugPrivilege() {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return FALSE;
    LUID luid;
    if (!LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid)) {
        CloseHandle(token);
        return FALSE;
    }
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(token);
    return ok && GetLastError() != ERROR_NOT_ALL_ASSIGNED;
}

BOOL MemFind(const BYTE* haystack, DWORD haystackLen, const BYTE* needle, DWORD needleLen) {
    if (needleLen > haystackLen) return FALSE;
    for (DWORD i = 0; i <= haystackLen - needleLen; i++) {
        if (memcmp(haystack + i, needle, needleLen) == 0)
            return TRUE;
    }
    return FALSE;
}

BOOL ScanFileForRaton(const WCHAR* filePath, std::vector<std::string>& matches) {
    matches.clear();
    if (_wcsicmp(filePath, ownPath) == 0) return FALSE;
    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize < 1024 || fileSize > 100 * 1024 * 1024) {
        CloseHandle(hFile);
        return FALSE;
    }

    BYTE* buf = (BYTE*)VirtualAlloc(NULL, fileSize, MEM_COMMIT, PAGE_READWRITE);
    if (!buf) { CloseHandle(hFile); return FALSE; }

    DWORD bytesRead;
    if (!ReadFile(hFile, buf, fileSize, &bytesRead, NULL) || bytesRead < 1024) {
        VirtualFree(buf, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);

    if (buf[0] != 'M' || buf[1] != 'Z') {
        VirtualFree(buf, 0, MEM_RELEASE);
        return FALSE;
    }

    int tier1 = 0, tier2 = 0;
    for (int i = 0; i < _countof(signatures); i++) {
        if (MemFind(buf, bytesRead, signatures[i].bytes, signatures[i].length)) {
            matches.push_back(signatures[i].name);
            if (signatures[i].tier == 1) tier1++;
            else tier2++;
        }
    }

    VirtualFree(buf, 0, MEM_RELEASE);
    return (tier1 >= 1 || tier2 >= 3);
}

void GetProcessExePath(DWORD pid, WCHAR* outPath, DWORD maxLen) {
    outPath[0] = 0;
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProc) {
        DWORD len = maxLen;
        QueryFullProcessImageNameW(hProc, 0, outPath, &len);
        CloseHandle(hProc);
    }
}

void ScanProcesses() {
    PrintColored(COLOR_CYAN, "[*] Scanning running processes...\n");

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    int scanned = 0;

    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID <= 4 || pe.th32ProcessID == ownPid) continue;

            WCHAR exePath[MAX_PATH * 2] = {};
            GetProcessExePath(pe.th32ProcessID, exePath, MAX_PATH * 2);
            if (exePath[0] == 0) continue;

            scanned++;
            std::vector<std::string> matches;
            if (ScanFileForRaton(exePath, matches)) {
                Detection d;
                d.path = exePath;
                d.pid = pe.th32ProcessID;
                d.processName = pe.szExeFile;
                d.type = 0;
                d.regHive = NULL;
                for (auto& m : matches)
                    d.matchName += m + ", ";
                if (!d.matchName.empty()) d.matchName.resize(d.matchName.size() - 2);
                detections.push_back(d);

                PrintColored(COLOR_RED, "  [!] DETECTED: %ls (PID %lu)\n", pe.szExeFile, pe.th32ProcessID);
                PrintColored(COLOR_YELLOW, "      Path: %ls\n", exePath);
                for (auto& m : matches)
                    PrintColored(COLOR_YELLOW, "      -> %s\n", m.c_str());
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    PrintColored(COLOR_WHITE, "  Scanned %d processes.\n", scanned);
}

void ScanDirectory(const WCHAR* dirPath) {
    WCHAR searchPath[MAX_PATH * 2];
    wsprintfW(searchPath, L"%s\\*", dirPath);

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(searchPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;

        WCHAR fullPath[MAX_PATH * 2];
        wsprintfW(fullPath, L"%s\\%s", dirPath, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            ScanDirectory(fullPath);
        } else {
            const WCHAR* ext = PathFindExtensionW(fd.cFileName);
            if (_wcsicmp(ext, L".exe") == 0 || _wcsicmp(ext, L".dll") == 0 || _wcsicmp(ext, L".scr") == 0) {
                std::vector<std::string> matches;
                if (ScanFileForRaton(fullPath, matches)) {
                    Detection d;
                    d.path = fullPath;
                    d.pid = 0;
                    d.type = 1;
                    d.regHive = NULL;
                    for (auto& m : matches) d.matchName += m + ", ";
                    if (!d.matchName.empty()) d.matchName.resize(d.matchName.size() - 2);
                    detections.push_back(d);
                    PrintColored(COLOR_RED, "  [!] Infected file: %ls\n", fullPath);
                }
            }
            if (wcsstr(fd.cFileName, L".BotKillerRaton")) {
                Detection d;
                d.path = fullPath;
                d.pid = 0;
                d.type = 1;
                d.matchName = ".BotKillerRaton artifact";
                d.regHive = NULL;
                detections.push_back(d);
                PrintColored(COLOR_YELLOW, "  [!] BotKiller artifact: %ls\n", fullPath);
            }
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
}

void ScanKnownLocations() {
    PrintColored(COLOR_CYAN, "\n[*] Scanning known Raton locations...\n");

    WCHAR appdata[MAX_PATH], localappdata[MAX_PATH];
    SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appdata);
    SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localappdata);

    const WCHAR* bases[] = { appdata, localappdata };
    const WCHAR* hideDirs[] = { L"PlatformRuntime" };

    for (int b = 0; b < 2; b++) {
        for (int h = 0; h < _countof(hideDirs); h++) {
            WCHAR dirPath[MAX_PATH * 2];
            wsprintfW(dirPath, L"%s\\%s", bases[b], hideDirs[h]);
            if (GetFileAttributesW(dirPath) != INVALID_FILE_ATTRIBUTES) {
                PrintColored(COLOR_RED, "  [!] Found hidden directory: %ls\n", dirPath);

                Detection d;
                d.path = dirPath;
                d.pid = 0;
                d.type = 1;
                d.matchName = "PlatformRuntime hide directory";
                d.regHive = NULL;
                detections.push_back(d);

                ScanDirectory(dirPath);
            }
        }
    }

    WCHAR tempBat[MAX_PATH * 2];
    wsprintfW(tempBat, L"%s\\Temp\\cleanup_*.bat", appdata);
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(tempBat, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            WCHAR fullPath[MAX_PATH * 2];
            wsprintfW(fullPath, L"%s\\Temp\\%s", appdata, fd.cFileName);
            Detection d;
            d.path = fullPath;
            d.pid = 0;
            d.type = 1;
            d.matchName = "Raton cleanup batch script";
            d.regHive = NULL;
            detections.push_back(d);
            PrintColored(COLOR_YELLOW, "  [!] Cleanup script: %ls\n", fullPath);
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }
}

void ScanRegistryKey(HKEY hive, const WCHAR* hiveName, const WCHAR* subkey) {
    HKEY hKey;
    if (RegOpenKeyExW(hive, subkey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) return;

    DWORD index = 0;
    WCHAR valueName[256];
    BYTE valueData[1024];
    DWORD nameLen, dataLen, type;

    while (TRUE) {
        nameLen = 256;
        dataLen = 1024;
        if (RegEnumValueW(hKey, index++, valueName, &nameLen, NULL, &type, valueData, &dataLen) != ERROR_SUCCESS)
            break;
        if (type != REG_SZ) continue;

        WCHAR* exePath = (WCHAR*)valueData;
        WCHAR cleanPath[MAX_PATH * 2];
        wcscpy_s(cleanPath, exePath);

        // strip quotes
        WCHAR* p = cleanPath;
        if (*p == L'"') p++;
        WCHAR* end = wcsrchr(p, L'"');
        if (end) *end = 0;

        if (wcsstr(p, L"PlatformRuntime")) {
            Detection d;
            d.path = p;
            d.pid = 0;
            d.type = 2;
            d.regHive = hive;
            d.regKey = subkey;
            d.regValue = valueName;
            d.matchName = "Registry Run key -> PlatformRuntime";
            detections.push_back(d);
            PrintColored(COLOR_RED, "  [!] %ls\\...\\Run\\%ls\n", hiveName, valueName);
            PrintColored(COLOR_YELLOW, "      -> %ls\n", exePath);
            continue;
        }

        if (GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES) {
            std::vector<std::string> matches;
            if (ScanFileForRaton(p, matches)) {
                Detection d;
                d.path = p;
                d.pid = 0;
                d.type = 2;
                d.regHive = hive;
                d.regKey = subkey;
                d.regValue = valueName;
                d.matchName = "Registry Run key -> Raton binary";
                detections.push_back(d);
                PrintColored(COLOR_RED, "  [!] %ls\\...\\Run\\%ls\n", hiveName, valueName);
                PrintColored(COLOR_YELLOW, "      -> %ls\n", exePath);
            }
        }
    }
    RegCloseKey(hKey);
}

void ScanRegistry() {
    PrintColored(COLOR_CYAN, "\n[*] Scanning registry persistence...\n");
    ScanRegistryKey(HKEY_CURRENT_USER, L"HKCU", L"Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    if (IsAdmin())
        ScanRegistryKey(HKEY_LOCAL_MACHINE, L"HKLM", L"Software\\Microsoft\\Windows\\CurrentVersion\\Run");
}

void ScanScheduledTasks() {
    PrintColored(COLOR_CYAN, "\n[*] Scanning Startup tasks...\n");

    if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED))) return;

    HRESULT secRes = CoInitializeSecurity(NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
    if (FAILED(secRes) && secRes != RPC_E_TOO_LATE) { CoUninitialize(); return; }

    ITaskService* pService = NULL;
    if (FAILED(CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
        IID_ITaskService, (void**)&pService))) { CoUninitialize(); return; }

    if (FAILED(pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t()))) {
        pService->Release(); CoUninitialize(); return;
    }

    ITaskFolder* pFolder = NULL;
    if (FAILED(pService->GetFolder(_bstr_t(L"\\"), &pFolder))) {
        pService->Release(); CoUninitialize(); return;
    }

    IRegisteredTaskCollection* pTasks = NULL;
    if (SUCCEEDED(pFolder->GetTasks(TASK_ENUM_HIDDEN, &pTasks))) {
        LONG count = 0;
        pTasks->get_Count(&count);
        for (LONG i = 1; i <= count; i++) {
            IRegisteredTask* pTask = NULL;
            if (FAILED(pTasks->get_Item(_variant_t(i), &pTask))) continue;

            BSTR name = NULL;
            pTask->get_Name(&name);

            ITaskDefinition* pDef = NULL;
            if (SUCCEEDED(pTask->get_Definition(&pDef))) {
                BSTR xml = NULL;
                if (SUCCEEDED(pDef->get_XmlText(&xml))) {
                    if (wcsstr(xml, L"PlatformRuntime")) {
                        Detection d;
                        d.pid = 0;
                        d.type = 3;
                        d.taskName = name ? name : L"unknown";
                        d.matchName = "Scheduled task -> PlatformRuntime";
                        d.regHive = NULL;
                        detections.push_back(d);
                        PrintColored(COLOR_RED, "  [!] Task: %ls \n", name);
                    } else {
                        IActionCollection* pActions = NULL;
                        if (SUCCEEDED(pDef->get_Actions(&pActions))) {
                            LONG ac = 0;
                            pActions->get_Count(&ac);
                            for (LONG a = 1; a <= ac; a++) {
                                IAction* pAction = NULL;
                                if (FAILED(pActions->get_Item(a, &pAction))) continue;
                                IExecAction* pExec = NULL;
                                if (SUCCEEDED(pAction->QueryInterface(IID_IExecAction, (void**)&pExec))) {
                                    BSTR actionPath = NULL;
                                    if (SUCCEEDED(pExec->get_Path(&actionPath)) && actionPath) {
                                        std::vector<std::string> matches;
                                        if (ScanFileForRaton(actionPath, matches)) {
                                            Detection d;
                                            d.path = actionPath;
                                            d.pid = 0;
                                            d.type = 3;
                                            d.taskName = name ? name : L"unknown";
                                            d.matchName = "Scheduled task -> Raton binary";
                                            d.regHive = NULL;
                                            detections.push_back(d);
                                            PrintColored(COLOR_RED, "  [!] Task: %ls -> %ls\n", name, actionPath);
                                        }
                                        SysFreeString(actionPath);
                                    }
                                    pExec->Release();
                                }
                                pAction->Release();
                            }
                            pActions->Release();
                        }
                    }
                    SysFreeString(xml);
                }
                pDef->Release();
            }
            if (name) SysFreeString(name);
            pTask->Release();
        }
        pTasks->Release();
    }

    pFolder->Release();
    pService->Release();
    CoUninitialize();
}

void DeepScan() {
    PrintColored(COLOR_CYAN, "\n[*] Deep scanning directories... (This May Take A While)\n");
    WCHAR appdata[MAX_PATH], localappdata[MAX_PATH], userprofile[MAX_PATH], startup[MAX_PATH];
    SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appdata);
    SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localappdata);
    SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, userprofile);
    SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, 0, startup);

    const WCHAR* dirs[] = { appdata, localappdata, startup };
    for (int i = 0; i < _countof(dirs); i++)
        ScanDirectory(dirs[i]);
}

BOOL KillProcess(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProc) return FALSE;
    BOOL ok = TerminateProcess(hProc, 1);
    CloseHandle(hProc);
    return ok;
}

BOOL DeleteFileForce(const WCHAR* path) {
    SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);
    return DeleteFileW(path);
}

BOOL RemoveDirectoryRecursive(const WCHAR* dir) {
    WCHAR search[MAX_PATH * 2];
    wsprintfW(search, L"%s\\*", dir);
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return RemoveDirectoryW(dir);

    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        WCHAR full[MAX_PATH * 2];
        wsprintfW(full, L"%s\\%s", dir, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            RemoveDirectoryRecursive(full);
        else
            DeleteFileForce(full);
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);

    SetFileAttributesW(dir, FILE_ATTRIBUTE_NORMAL);
    return RemoveDirectoryW(dir);
}

BOOL DeleteScheduledTask(const WCHAR* name) {
    BOOL result = FALSE;
    if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED))) return FALSE;

    HRESULT secRes = CoInitializeSecurity(NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
    if (FAILED(secRes) && secRes != RPC_E_TOO_LATE) { CoUninitialize(); return FALSE; }

    ITaskService* pService = NULL;
    if (SUCCEEDED(CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
        IID_ITaskService, (void**)&pService))) {
        if (SUCCEEDED(pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t()))) {
            ITaskFolder* pFolder = NULL;
            if (SUCCEEDED(pService->GetFolder(_bstr_t(L"\\"), &pFolder))) {
                if (SUCCEEDED(pFolder->DeleteTask(_bstr_t(name), 0)))
                    result = TRUE;
                pFolder->Release();
            }
        }
        pService->Release();
    }
    CoUninitialize();
    return result;
}

void RemoveDefenderExclusions() {
    if (!IsAdmin()) return;

    WCHAR cmd[] = L"powershell.exe";
    WCHAR args[] = L"-NoProfile -Command \"$prefs = Get-MpPreference; foreach($p in $prefs.ExclusionProcess) { if($p -like '*PlatformRuntime*') { Remove-MpPreference -ExclusionProcess $p } }\"";

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi;
    WCHAR cmdLine[2048];
    wsprintfW(cmdLine, L"%s %s", cmd, args);
    if (CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 10000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        PrintColored(COLOR_GREEN, "    [+] Cleaned Defender exclusions\n");
    }
}

void Banner() {
    SetColor(COLOR_RED);
    printf("\n");
    printf("  ============================================================\n");
    printf("  ||                                                        ||\n");
    printf("  ||              RATON RAT REMOVAL TOOL                    ||\n");
    printf("  ||   https://github.com/agarthanfaccist/RatonRAT-Remover  ||\n");
    printf("  ============================================================\n");
    SetColor(COLOR_WHITE);
    printf("\n");
}

int main() {
    hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    ownPid = GetCurrentProcessId();
    GetModuleFileNameW(NULL, ownPath, MAX_PATH * 2);
    Banner();

    if (IsAdmin()) {
        PrintColored(COLOR_GREEN, "[+] Running as Administrator\n\n");
        EnableDebugPrivilege();
    } else {
        PrintColored(COLOR_YELLOW, "[!] Not running as Administrator. Some Stuff may fail.\n");

    }

    ScanProcesses();
    ScanKnownLocations();
    ScanRegistry();
    ScanScheduledTasks();
    DeepScan();

    printf("\n");
    PrintColored(COLOR_WHITE, "==================================\n");

    if (detections.empty()) {
        PrintColored(COLOR_GREEN, "\n[+] CLEAN\n\n");
        system("pause");
        return 0;
    }

    int procCount = 0, fileCount = 0, regCount = 0, taskCount = 0;
    for (auto& d : detections) {
        switch (d.type) {
            case 0: procCount++; break;
            case 1: fileCount++; break;
            case 2: regCount++; break;
            case 3: taskCount++; break;
        }
    }

    printf("\n");
    PrintColored(COLOR_RED, "[!] INFECTION FOUND:\n");
    PrintColored(COLOR_RED, "    Processes:     %d\n", procCount);
    PrintColored(COLOR_RED, "    Files:         %d\n", fileCount);
    PrintColored(COLOR_RED, "    Registry keys: %d\n", regCount);
    PrintColored(COLOR_RED, "    Sched. tasks:  %d\n", taskCount);
    printf("\n");
    PrintColored(COLOR_YELLOW, "Do you wanna delete all found traces? (y/n): ");
    char answer = 0;
    scanf_s(" %c", &answer, 1);

    if (answer != 'y' && answer != 'Y') {
        PrintColored(COLOR_CYAN, "\n[*] No changes made.\n\n");
        system("pause");
        return 0;
    }
    printf("\n");

    PrintColored(COLOR_CYAN, "[*] Killing infected processes...\n");
    for (auto& d : detections) {
        if (d.type == 0 && d.pid > 0) {
            if (KillProcess(d.pid))
                PrintColored(COLOR_GREEN, "    [+] Killed PID %lu (%ls)\n", d.pid, d.processName.c_str());
            else
                PrintColored(COLOR_RED, "    [-] Failed PID %lu\n", d.pid);
        }
    }
    Sleep(2000);

    PrintColored(COLOR_CYAN, "\n[*] Removing registry entries...\n");
    for (auto& d : detections) {
        if (d.type == 2 && d.regHive) {
            HKEY hKey;
            if (RegOpenKeyExW(d.regHive, d.regKey.c_str(), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
                if (RegDeleteValueW(hKey, d.regValue.c_str()) == ERROR_SUCCESS)
                    PrintColored(COLOR_GREEN, "    [+] Removed: %ls\n", d.regValue.c_str());
                else
                    PrintColored(COLOR_RED, "    [-] Failed: %ls\n", d.regValue.c_str());
                RegCloseKey(hKey);
            }
        }
    }

    PrintColored(COLOR_CYAN, "\n[*] Removing scheduled tasks...\n");
    for (auto& d : detections) {
        if (d.type == 3 && !d.taskName.empty()) {
            if (DeleteScheduledTask(d.taskName.c_str()))
                PrintColored(COLOR_GREEN, "    [+] Removed task: %ls\n", d.taskName.c_str());
            else
                PrintColored(COLOR_RED, "    [-] Failed task: %ls\n", d.taskName.c_str());
        }
    }

    PrintColored(COLOR_CYAN, "\n[*] Deleting files and directories...\n");
    for (auto& d : detections) {
        if (d.type != 1) continue;
        if (d.matchName == "PlatformRuntime hide directory") {
            if (RemoveDirectoryRecursive(d.path.c_str()))
                PrintColored(COLOR_GREEN, "    [+] Removed dir: %ls\n", d.path.c_str());
            else
                PrintColored(COLOR_RED, "    [-] Failed dir: %ls\n", d.path.c_str());
        } else {
            if (DeleteFileForce(d.path.c_str()))
                PrintColored(COLOR_GREEN, "    [+] Deleted: %ls\n", d.path.c_str());
            else
                PrintColored(COLOR_RED, "    [-] Failed: %ls\n", d.path.c_str());
        }
    }
    for (auto& d : detections) {
        if (d.type == 0 && !d.path.empty()) {
            DeleteFileForce(d.path.c_str());
        }
    }

    PrintColored(COLOR_CYAN, "\n[*] Cleaning Defender exclusions...\n");
    RemoveDefenderExclusions();
    printf("\n");
    WCHAR appdata[MAX_PATH], localappdata[MAX_PATH];
    SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appdata);
    SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localappdata);

    WCHAR chk1[MAX_PATH * 2], chk2[MAX_PATH * 2];
    wsprintfW(chk1, L"%s\\PlatformRuntime", appdata);
    wsprintfW(chk2, L"%s\\PlatformRuntime", localappdata);

    BOOL clean = TRUE;
    if (GetFileAttributesW(chk1) != INVALID_FILE_ATTRIBUTES) {
        PrintColored(COLOR_RED, "  [!] Still exists: %ls\n", chk1);
        clean = FALSE;
    }
    if (GetFileAttributesW(chk2) != INVALID_FILE_ATTRIBUTES) {
        PrintColored(COLOR_RED, "  [!] Still exists: %ls\n", chk2);
        clean = FALSE;
    }

    if (clean) {
        printf("\n");
        PrintColored(COLOR_GREEN, "[+] REMOVAL COMPLETE.\n");
        PrintColored(COLOR_GREEN, "    Reboot is recommended.\n\n");
    } else {
        printf("\n");
        PrintColored(COLOR_YELLOW, "[!] Some traces remain. Try rebooting into Safe Mode and run again.\n\n");
    }

    system("pause");
    return 0;
}
