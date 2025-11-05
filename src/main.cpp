#include <windows.h>
#include <commctrl.h>
#include <shobjidl.h> // IFileOpenDialog
#include <shellapi.h> // ShellExecuteExW
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <winver.h>
#include <cwctype>
#include <unordered_set>
#include "pe_utils.h"

#pragma comment(lib, "Comctl32.lib")
#pragma comment(lib, "Version.lib")

/* Control IDs */
#define IDC_OPEN_BTN     1001
#define IDC_REG_BTN      1002
#define IDC_LIST         1003
#define IDC_LOG          1004
#define IDC_REG_ELEV     1005
#define IDC_CLEAR_LOG    1006
#define IDC_REG_DIFF     1007
#define IDC_EXPORT_LOG   1008
#define IDC_UNREG        1009

// Window class name
static const wchar_t* kClassName = L"DependencyExplorerWnd";

// Globals (per-window state)
struct AppState {
    std::wstring selectedDllPath;
    peutils::MachineType selectedDllMachine = peutils::MachineType::Unknown;
    HWND hList = nullptr;
    HWND hLog  = nullptr;
    HWND hOpenBtn = nullptr;
    HWND hRegBtn  = nullptr;
    HWND hRegElevBtn = nullptr;
    HWND hClearLogBtn = nullptr;
    HWND hRegDiffBtn = nullptr;
    HWND hExportLogBtn = nullptr;
    HWND hUnregBtn = nullptr;

    // Registry snapshots around registration (before/after)
    std::vector<std::wstring> regSnapBefore;
    std::vector<std::wstring> regSnapAfter;
};

static std::wstring DirName(const std::wstring& path) {
    size_t pos = path.find_last_of(L"\\/"); 
    if (pos == std::wstring::npos) return L"";
    return path.substr(0, pos);
}

static void AppendLog(HWND hEdit, const std::wstring& line) {
    // Ensure CRLF line end
    std::wstring out = line;
    if (out.size() < 2 || out.substr(out.size()-2) != L"\r\n") {
        out += L"\r\n";
    }
    int len = GetWindowTextLengthW(hEdit);
    SendMessageW(hEdit, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessageW(hEdit, EM_REPLACESEL, FALSE, (LPARAM)out.c_str());
}

static void ClearList(HWND hList) {
    ListView_DeleteAllItems(hList);
}

static void InitListViewColumns(HWND hList) {
    // Clear existing columns
    while (ListView_DeleteColumn(hList, 0)) {}
    LVCOLUMNW col{};
    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

    col.iSubItem = 0;
    col.cx = 220;
    col.pszText = const_cast<LPWSTR>(L"DLL Name");
    ListView_InsertColumn(hList, 0, &col);

    col.iSubItem = 1;
    col.cx = 600;
    col.pszText = const_cast<LPWSTR>(L"Resolved Path");
    ListView_InsertColumn(hList, 1, &col);

    col.iSubItem = 2;
    col.cx = 360;
    col.pszText = const_cast<LPWSTR>(L"Description");
    ListView_InsertColumn(hList, 2, &col);

    col.iSubItem = 3;
    col.cx = 280;
    col.pszText = const_cast<LPWSTR>(L"Company");
    ListView_InsertColumn(hList, 3, &col);

    ListView_SetExtendedListViewStyleEx(hList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
}

static std::wstring ResolvePathWithGetModuleFileName(const std::wstring& dllName, const std::wstring& primaryDir) {
    auto getPathFromModule = [](HMODULE mod) -> std::wstring {
        if (!mod) return L"";
        // Try small buffer first
        wchar_t buf[MAX_PATH];
        DWORD n = GetModuleFileNameW(mod, buf, MAX_PATH);
        if (n > 0 && n < MAX_PATH) return std::wstring(buf, n);
        // Fallback to larger buffer if needed
        std::wstring result;
        DWORD size = MAX_PATH * 4;
        for (int i = 0; i < 3; ++i) {
            std::vector<wchar_t> big(size);
            n = GetModuleFileNameW(mod, big.data(), size);
            if (n > 0 && n < size) {
                result.assign(big.data(), n);
                break;
            }
            size *= 2;
        }
        return result;
    };

    // 1) Try same directory as the selected DLL
    if (!primaryDir.empty()) {
        std::wstring candidate = primaryDir;
        if (!candidate.empty() && candidate.back() != L'\\' && candidate.back() != L'/') {
            candidate += L'\\';
        }
        candidate += dllName;
        HMODULE h = LoadLibraryExW(candidate.c_str(), nullptr, LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE);
        if (h) {
            std::wstring path = getPathFromModule(h);
            FreeLibrary(h);
            if (!path.empty()) return path;
        }
    }

    // 2) Try System32 explicitly
    {
        HMODULE h = LoadLibraryExW(dllName.c_str(), nullptr, LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE | LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (h) {
            std::wstring path = getPathFromModule(h);
            FreeLibrary(h);
            if (!path.empty()) return path;
        }
    }

    // 3) Use default search order
    {
        HMODULE h = LoadLibraryExW(dllName.c_str(), nullptr, LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE);
        if (h) {
            std::wstring path = getPathFromModule(h);
            FreeLibrary(h);
            if (!path.empty()) return path;
        }
    }

    return L"";
}

static std::wstring GetFileDescription(const std::wstring& filePath) {
    if (filePath.empty()) return L"";
    DWORD handle = 0;
    DWORD size = GetFileVersionInfoSizeW(filePath.c_str(), &handle);
    if (!size) return L"";
    std::vector<BYTE> data(size);
    if (!GetFileVersionInfoW(filePath.c_str(), 0, size, data.data())) return L"";

    struct LANGANDCODEPAGE { WORD wLanguage; WORD wCodePage; };
    LANGANDCODEPAGE* lpTranslate = nullptr;
    UINT cbTranslate = 0;
    if (VerQueryValueW(data.data(), L"\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &cbTranslate) && cbTranslate >= sizeof(LANGANDCODEPAGE)) {
        UINT count = cbTranslate / sizeof(LANGANDCODEPAGE);
        for (UINT i = 0; i < count; ++i) {
            wchar_t subBlock[64];
            swprintf(subBlock, 64, L"\\StringFileInfo\\%04x%04x\\FileDescription", lpTranslate[i].wLanguage, lpTranslate[i].wCodePage);
            LPWSTR value = nullptr;
            UINT cch = 0;
            if (VerQueryValueW(data.data(), subBlock, (LPVOID*)&value, &cch) && value && cch > 0) {
                return std::wstring(value);
            }
        }
    }

    // Fallback to US English, Unicode codepage
    LPWSTR value = nullptr;
    UINT cch = 0;
    if (VerQueryValueW(data.data(), L"\\StringFileInfo\\040904b0\\FileDescription", (LPVOID*)&value, &cch) && value && cch > 0) {
        return std::wstring(value);
    }

    // Secondary fallback: ProductName if FileDescription missing
    if (VerQueryValueW(data.data(), L"\\StringFileInfo\\040904b0\\ProductName", (LPVOID*)&value, &cch) && value && cch > 0) {
        return std::wstring(value);
    }
    return L"";
}

static std::wstring GetFileCompanyName(const std::wstring& filePath) {
    if (filePath.empty()) return L"";
    DWORD handle = 0;
    DWORD size = GetFileVersionInfoSizeW(filePath.c_str(), &handle);
    if (!size) return L"";
    std::vector<BYTE> data(size);
    if (!GetFileVersionInfoW(filePath.c_str(), 0, size, data.data())) return L"";

    struct LANGANDCODEPAGE { WORD wLanguage; WORD wCodePage; };
    LANGANDCODEPAGE* lpTranslate = nullptr;
    UINT cbTranslate = 0;
    if (VerQueryValueW(data.data(), L"\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &cbTranslate) && cbTranslate >= sizeof(LANGANDCODEPAGE)) {
        UINT count = cbTranslate / sizeof(LANGANDCODEPAGE);
        for (UINT i = 0; i < count; ++i) {
            wchar_t subBlock[64];
            swprintf(subBlock, 64, L"\\StringFileInfo\\%04x%04x\\CompanyName", lpTranslate[i].wLanguage, lpTranslate[i].wCodePage);
            LPWSTR value = nullptr;
            UINT cch = 0;
            if (VerQueryValueW(data.data(), subBlock, (LPVOID*)&value, &cch) && value && cch > 0) {
                return std::wstring(value);
            }
        }
    }

    // Fallback to US English, Unicode codepage
    LPWSTR value = nullptr;
    UINT cch = 0;
    if (VerQueryValueW(data.data(), L"\\StringFileInfo\\040904b0\\CompanyName", (LPVOID*)&value, &cch) && value && cch > 0) {
        return std::wstring(value);
    }
    return L"";
}

static std::wstring ToLower(const std::wstring& s) {
    std::wstring out = s;
    for (auto& ch : out) ch = static_cast<wchar_t>(towlower(ch));
    return out;
}

static bool ContainsIC(const std::wstring& haystack, const std::wstring& needle) {
    if (needle.empty()) return true;
    std::wstring h = ToLower(haystack);
    std::wstring n = ToLower(needle);
    return h.find(n) != std::wstring::npos;
}

struct RegSearchOptions {
    REGSAM wow64View;
    int maxDepth;
    int maxNodes;
};

static void SearchRegistryForPathInternal(HKEY root, const std::wstring& subkey, const std::wstring& pathLower, const std::wstring& rootLabel,
                                          const RegSearchOptions& opt, int depth, int& visited,
                                          std::vector<std::wstring>& out) {
    if (depth > opt.maxDepth || visited > opt.maxNodes) return;

    HKEY hKey = nullptr;
    LONG rc = RegOpenKeyExW(root, subkey.c_str(), 0, KEY_READ | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | opt.wow64View, &hKey);
    if (rc != ERROR_SUCCESS) return;

    ++visited;

    // Check default value
    DWORD type = 0;
    DWORD cb = 0;
    if (RegQueryValueExW(hKey, nullptr, nullptr, &type, nullptr, &cb) == ERROR_SUCCESS &&
        (type == REG_SZ || type == REG_EXPAND_SZ) && cb > sizeof(wchar_t)) {
        std::vector<wchar_t> buf(cb / sizeof(wchar_t) + 1);
        if (RegQueryValueExW(hKey, nullptr, nullptr, &type, reinterpret_cast<LPBYTE>(buf.data()), &cb) == ERROR_SUCCESS) {
            std::wstring val(buf.data());
            if (ContainsIC(val, pathLower)) {
                out.push_back(rootLabel + L"\\" + subkey + L" [(Default)] = " + val);
            }
        }
    }

    // Enumerate values
    DWORD index = 0;
    for (;;) {
        DWORD nameLen = 256;
        wchar_t nameBuf[256];
        DWORD typeV = 0;
        DWORD dataSize = 0;
        LONG r = RegEnumValueW(hKey, index, nameBuf, &nameLen, nullptr, &typeV, nullptr, &dataSize);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r == ERROR_MORE_DATA) { // grow buffers and retry
            std::vector<wchar_t> nameDyn(1024);
            nameLen = static_cast<DWORD>(nameDyn.size());
            dataSize = 65536;
            std::vector<BYTE> dataDyn(dataSize);
            r = RegEnumValueW(hKey, index, nameDyn.data(), &nameLen, nullptr, &typeV, dataDyn.data(), &dataSize);
            if (r == ERROR_SUCCESS && (typeV == REG_SZ || typeV == REG_EXPAND_SZ)) {
                std::wstring val(reinterpret_cast<wchar_t*>(dataDyn.data()));
                if (ContainsIC(val, pathLower)) {
                    out.push_back(rootLabel + L"\\" + subkey + L" [" + std::wstring(nameDyn.data(), nameLen) + L"] = " + val);
                }
            }
            ++index;
            continue;
        }
        if (r == ERROR_SUCCESS) {
            std::wstring valueName(nameBuf, nameLen);
            if ((typeV == REG_SZ || typeV == REG_EXPAND_SZ) && dataSize > sizeof(wchar_t)) {
                std::vector<wchar_t> data(dataSize / sizeof(wchar_t) + 1);
                DWORD ds = dataSize;
                if (RegEnumValueW(hKey, index, nameBuf, &nameLen, nullptr, &typeV, reinterpret_cast<LPBYTE>(data.data()), &ds) == ERROR_SUCCESS) {
                    std::wstring val(data.data());
                    if (ContainsIC(val, pathLower)) {
                        out.push_back(rootLabel + L"\\" + subkey + L" [" + valueName + L"] = " + val);
                    }
                }
            }
        }
        ++index;
    }

    // Enumerate subkeys
    DWORD subIndex = 0;
    for (;;) {
        wchar_t subName[256];
        DWORD subNameLen = 256;
        FILETIME ft{};
        LONG rr = RegEnumKeyExW(hKey, subIndex, subName, &subNameLen, nullptr, nullptr, nullptr, &ft);
        if (rr == ERROR_NO_MORE_ITEMS) break;
        if (rr == ERROR_SUCCESS) {
            std::wstring child = subkey.empty() ? std::wstring(subName, subNameLen)
                                                : subkey + L"\\" + std::wstring(subName, subNameLen);
            SearchRegistryForPathInternal(root, child, pathLower, rootLabel, opt, depth + 1, visited, out);
        }
        ++subIndex;
        if (visited > opt.maxNodes) break;
    }

    RegCloseKey(hKey);
}

static void SearchRegistryForPath(HKEY root, const std::wstring& rootLabel, const std::wstring& subkey, const std::wstring& pathLower,
                                  const RegSearchOptions& opt, std::vector<std::wstring>& out) {
    int visited = 0;
    SearchRegistryForPathInternal(root, subkey, pathLower, rootLabel, opt, 0, visited, out);
}

static void ListRegistryWritesForDll(const std::wstring& dllPath, HWND hLog) {
    if (!hLog || dllPath.empty()) return;
    std::wstring pathLower = ToLower(dllPath);

    std::vector<std::wstring> results;
    std::unordered_set<std::wstring> seen;

    auto addUnique = [&](const std::vector<std::wstring>& v) {
        for (const auto& s : v) {
            if (seen.insert(s).second) results.push_back(s);
        }
    };

    // Limit traversal to a reasonable scope to keep UI responsive
    RegSearchOptions opt64{ KEY_WOW64_64KEY, 4, 20000 };
    RegSearchOptions opt32{ KEY_WOW64_32KEY, 4, 20000 };

    // Scan HKCR\CLSID and HKCR\TypeLib for references to the DLL path (both 64-bit and 32-bit views)
    std::vector<std::wstring> tmp;
    // HKCR (merged view)
    tmp.clear(); SearchRegistryForPath(HKEY_CLASSES_ROOT, L"HKCR", L"CLSID", pathLower, opt64, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_CLASSES_ROOT, L"HKCR", L"TypeLib", pathLower, opt64, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_CLASSES_ROOT, L"HKCR", L"Interface", pathLower, opt64, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_CLASSES_ROOT, L"HKCR", L"AppID", pathLower, opt64, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_CLASSES_ROOT, L"HKCR", L"CLSID", pathLower, opt32, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_CLASSES_ROOT, L"HKCR", L"TypeLib", pathLower, opt32, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_CLASSES_ROOT, L"HKCR", L"Interface", pathLower, opt32, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_CLASSES_ROOT, L"HKCR", L"AppID", pathLower, opt32, tmp); addUnique(tmp);
    // HKLM\SOFTWARE\Classes (machine)
    tmp.clear(); SearchRegistryForPath(HKEY_LOCAL_MACHINE, L"HKLM\\SOFTWARE\\Classes", L"SOFTWARE\\Classes\\CLSID", pathLower, opt64, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_LOCAL_MACHINE, L"HKLM\\SOFTWARE\\Classes", L"SOFTWARE\\Classes\\TypeLib", pathLower, opt64, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_LOCAL_MACHINE, L"HKLM\\SOFTWARE\\Classes", L"SOFTWARE\\Classes\\Interface", pathLower, opt64, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_LOCAL_MACHINE, L"HKLM\\SOFTWARE\\Classes", L"SOFTWARE\\Classes\\AppID", pathLower, opt64, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_LOCAL_MACHINE, L"HKLM\\SOFTWARE\\Classes", L"SOFTWARE\\Classes\\CLSID", pathLower, opt32, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_LOCAL_MACHINE, L"HKLM\\SOFTWARE\\Classes", L"SOFTWARE\\Classes\\TypeLib", pathLower, opt32, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_LOCAL_MACHINE, L"HKLM\\SOFTWARE\\Classes", L"SOFTWARE\\Classes\\Interface", pathLower, opt32, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_LOCAL_MACHINE, L"HKLM\\SOFTWARE\\Classes", L"SOFTWARE\\Classes\\AppID", pathLower, opt32, tmp); addUnique(tmp);
    // HKCU\Software\Classes (per-user)
    tmp.clear(); SearchRegistryForPath(HKEY_CURRENT_USER, L"HKCU\\Software\\Classes", L"Software\\Classes\\CLSID", pathLower, opt64, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_CURRENT_USER, L"HKCU\\Software\\Classes", L"Software\\Classes\\TypeLib", pathLower, opt64, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_CURRENT_USER, L"HKCU\\Software\\Classes", L"Software\\Classes\\Interface", pathLower, opt64, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_CURRENT_USER, L"HKCU\\Software\\Classes", L"Software\\Classes\\AppID", pathLower, opt64, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_CURRENT_USER, L"HKCU\\Software\\Classes", L"Software\\Classes\\CLSID", pathLower, opt32, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_CURRENT_USER, L"HKCU\\Software\\Classes", L"Software\\Classes\\TypeLib", pathLower, opt32, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_CURRENT_USER, L"HKCU\\Software\\Classes", L"Software\\Classes\\Interface", pathLower, opt32, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_CURRENT_USER, L"HKCU\\Software\\Classes", L"Software\\Classes\\AppID", pathLower, opt32, tmp); addUnique(tmp);

    if (results.empty()) {
        AppendLog(hLog, L"[Info] No registry entries referencing this DLL were found under HKCR\\CLSID or HKCR\\TypeLib.");
        return;
    }

    AppendLog(hLog, L"[Info] Registry entries referencing this DLL path:");
    for (const auto& line : results) {
        AppendLog(hLog, L"  - " + line);
    }
}

static void CollectProgIDsForDllFromHKCR(const std::wstring& dllPathLower, REGSAM wow64View, std::unordered_set<std::wstring>& outProgIDs) {
    HKEY hClsid = nullptr;
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, L"CLSID", 0, KEY_READ | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | wow64View, &hClsid) != ERROR_SUCCESS) {
        return;
    }
    DWORD index = 0;
    for (;;) {
        wchar_t subName[256];
        DWORD subNameLen = 256;
        FILETIME ft{};
        LONG r = RegEnumKeyExW(hClsid, index, subName, &subNameLen, nullptr, nullptr, nullptr, &ft);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r == ERROR_SUCCESS) {
            std::wstring guid(subName, subNameLen);
            std::wstring inprocKey = L"CLSID\\" + guid + L"\\InprocServer32";
            HKEY hInproc = nullptr;
            if (RegOpenKeyExW(HKEY_CLASSES_ROOT, inprocKey.c_str(), 0, KEY_READ | KEY_QUERY_VALUE | wow64View, &hInproc) == ERROR_SUCCESS) {
                DWORD type = 0;
                DWORD cb = 0;
                if (RegQueryValueExW(hInproc, nullptr, nullptr, &type, nullptr, &cb) == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ) && cb > sizeof(wchar_t)) {
                    std::vector<wchar_t> buf(cb / sizeof(wchar_t) + 1);
                    if (RegQueryValueExW(hInproc, nullptr, nullptr, &type, reinterpret_cast<LPBYTE>(buf.data()), &cb) == ERROR_SUCCESS) {
                        std::wstring path = buf.data();
                        if (ContainsIC(path, dllPathLower)) {
                            // Get ProgID
                            RegCloseKey(hInproc);
                            std::wstring progidKey = L"CLSID\\" + guid;
                            HKEY hGuid = nullptr;
                            if (RegOpenKeyExW(HKEY_CLASSES_ROOT, progidKey.c_str(), 0, KEY_READ | KEY_QUERY_VALUE | wow64View, &hGuid) == ERROR_SUCCESS) {
                                DWORD type2 = 0, cb2 = 0;
                                if (RegQueryValueExW(hGuid, L"ProgID", nullptr, &type2, nullptr, &cb2) == ERROR_SUCCESS && (type2 == REG_SZ || type2 == REG_EXPAND_SZ) && cb2 > sizeof(wchar_t)) {
                                    std::vector<wchar_t> buf2(cb2 / sizeof(wchar_t) + 1);
                                    if (RegQueryValueExW(hGuid, L"ProgID", nullptr, &type2, reinterpret_cast<LPBYTE>(buf2.data()), &cb2) == ERROR_SUCCESS) {
                                        std::wstring progid = buf2.data();
                                        if (!progid.empty()) outProgIDs.insert(progid);
                                    }
                                }
                                RegCloseKey(hGuid);
                            }
                            index++;
                            continue;
                        }
                    }
                }
                RegCloseKey(hInproc);
            }
        }
        ++index;
    }
    RegCloseKey(hClsid);
}

static void ListOfficeLoadBehaviorForDll(const std::wstring& dllPath, HWND hLog) {
    if (!hLog || dllPath.empty()) return;
    std::wstring pathLower = ToLower(dllPath);

    // Collect ProgIDs for CLSIDs whose InprocServer32 points to this DLL
    std::unordered_set<std::wstring> progIds;
    CollectProgIDsForDllFromHKCR(pathLower, KEY_WOW64_64KEY, progIds);
    CollectProgIDsForDllFromHKCR(pathLower, KEY_WOW64_32KEY, progIds);

    if (progIds.empty()) {
        AppendLog(hLog, L"[Info] No COM ProgID associated with this DLL via InprocServer32; skipping Office LoadBehavior scan.");
        return;
    }

    const std::wstring officeBase = L"Software\\Microsoft\\Office\\";
    const std::vector<std::wstring> apps = { L"Outlook", L"Excel", L"Word", L"PowerPoint", L"Visio", L"Project", L"Access", L"OneNote", L"Publisher" };

    auto scanRoot = [&](HKEY root, const std::wstring& rootLabel, REGSAM view) {
        for (const auto& app : apps) {
            for (const auto& progId : progIds) {
                std::wstring subkey = officeBase + app + L"\\Addins\\" + progId;
                HKEY hKey = nullptr;
                LONG rc = RegOpenKeyExW(root, subkey.c_str(), 0, KEY_READ | KEY_QUERY_VALUE | view, &hKey);
                if (rc != ERROR_SUCCESS) continue;

                DWORD type = 0;
                DWORD cb = sizeof(DWORD);
                DWORD dw = 0;
                if (RegQueryValueExW(hKey, L"LoadBehavior", nullptr, &type, reinterpret_cast<LPBYTE>(&dw), &cb) == ERROR_SUCCESS && type == REG_DWORD) {
                    std::wstringstream ss;
                    ss << L"[Info] " << rootLabel << L"\\" << subkey << L"\\LoadBehavior = " << dw << L" (0x" << std::hex << std::uppercase << dw << L")";
                    AppendLog(hLog, ss.str());
                }
                RegCloseKey(hKey);
            }
        }
    };

    AppendLog(hLog, L"[Info] Checking Office Add-ins LoadBehavior for related ProgIDs...");
    scanRoot(HKEY_CURRENT_USER, L"HKCU", KEY_WOW64_64KEY);
    scanRoot(HKEY_CURRENT_USER, L"HKCU", KEY_WOW64_32KEY);
    scanRoot(HKEY_LOCAL_MACHINE, L"HKLM", KEY_WOW64_64KEY);
    scanRoot(HKEY_LOCAL_MACHINE, L"HKLM", KEY_WOW64_32KEY);
}

static void TakeRegistrySnapshotForDll(const std::wstring& dllPath, std::vector<std::wstring>& out) {
    out.clear();
    if (dllPath.empty()) return;
    std::wstring pathLower = ToLower(dllPath);

    std::vector<std::wstring> tmp;
    std::unordered_set<std::wstring> seen;
    auto addUnique = [&](const std::vector<std::wstring>& v) {
        for (const auto& s : v) {
            if (seen.insert(s).second) out.push_back(s);
        }
    };

    RegSearchOptions opt64{ KEY_WOW64_64KEY, 4, 20000 };
    RegSearchOptions opt32{ KEY_WOW64_32KEY, 4, 20000 };

    // HKCR (merged)
    tmp.clear(); SearchRegistryForPath(HKEY_CLASSES_ROOT, L"HKCR", L"CLSID", pathLower, opt64, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_CLASSES_ROOT, L"HKCR", L"TypeLib", pathLower, opt64, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_CLASSES_ROOT, L"HKCR", L"Interface", pathLower, opt64, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_CLASSES_ROOT, L"HKCR", L"AppID", pathLower, opt64, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_CLASSES_ROOT, L"HKCR", L"CLSID", pathLower, opt32, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_CLASSES_ROOT, L"HKCR", L"TypeLib", pathLower, opt32, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_CLASSES_ROOT, L"HKCR", L"Interface", pathLower, opt32, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_CLASSES_ROOT, L"HKCR", L"AppID", pathLower, opt32, tmp); addUnique(tmp);

    // HKLM\SOFTWARE\Classes
    tmp.clear(); SearchRegistryForPath(HKEY_LOCAL_MACHINE, L"HKLM\\SOFTWARE\\Classes", L"SOFTWARE\\Classes\\CLSID", pathLower, opt64, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_LOCAL_MACHINE, L"HKLM\\SOFTWARE\\Classes", L"SOFTWARE\\Classes\\TypeLib", pathLower, opt64, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_LOCAL_MACHINE, L"HKLM\\SOFTWARE\\Classes", L"SOFTWARE\\Classes\\Interface", pathLower, opt64, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_LOCAL_MACHINE, L"HKLM\\SOFTWARE\\Classes", L"SOFTWARE\\Classes\\AppID", pathLower, opt64, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_LOCAL_MACHINE, L"HKLM\\SOFTWARE\\Classes", L"SOFTWARE\\Classes\\CLSID", pathLower, opt32, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_LOCAL_MACHINE, L"HKLM\\SOFTWARE\\Classes", L"SOFTWARE\\Classes\\TypeLib", pathLower, opt32, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_LOCAL_MACHINE, L"HKLM\\SOFTWARE\\Classes", L"SOFTWARE\\Classes\\Interface", pathLower, opt32, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_LOCAL_MACHINE, L"HKLM\\SOFTWARE\\Classes", L"SOFTWARE\\Classes\\AppID", pathLower, opt32, tmp); addUnique(tmp);

    // HKCU\Software\Classes
    tmp.clear(); SearchRegistryForPath(HKEY_CURRENT_USER, L"HKCU\\Software\\Classes", L"Software\\Classes\\CLSID", pathLower, opt64, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_CURRENT_USER, L"HKCU\\Software\\Classes", L"Software\\Classes\\TypeLib", pathLower, opt64, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_CURRENT_USER, L"HKCU\\Software\\Classes", L"Software\\Classes\\Interface", pathLower, opt64, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_CURRENT_USER, L"HKCU\\Software\\Classes", L"Software\\Classes\\AppID", pathLower, opt64, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_CURRENT_USER, L"HKCU\\Software\\Classes", L"Software\\Classes\\CLSID", pathLower, opt32, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_CURRENT_USER, L"HKCU\\Software\\Classes", L"Software\\Classes\\TypeLib", pathLower, opt32, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_CURRENT_USER, L"HKCU\\Software\\Classes", L"Software\\Classes\\Interface", pathLower, opt32, tmp); addUnique(tmp);
    tmp.clear(); SearchRegistryForPath(HKEY_CURRENT_USER, L"HKCU\\Software\\Classes", L"Software\\Classes\\AppID", pathLower, opt32, tmp); addUnique(tmp);
}

static void ComputeAndLogRegistryDiff(HWND hLog, const std::vector<std::wstring>& before, const std::vector<std::wstring>& after) {
    std::unordered_set<std::wstring> bset(before.begin(), before.end());
    std::unordered_set<std::wstring> aset(after.begin(), after.end());

    std::vector<std::wstring> added, removed;
    for (const auto& s : after) if (!bset.count(s)) added.push_back(s);
    for (const auto& s : before) if (!aset.count(s)) removed.push_back(s);

    if (added.empty() && removed.empty()) {
        AppendLog(hLog, L"[Diff] No registry differences detected between snapshots.");
        return;
    }
    std::wstringstream ss;
    ss << L"[Diff] Added: " << added.size() << L", Removed: " << removed.size();
    AppendLog(hLog, ss.str());

    if (!added.empty()) {
        AppendLog(hLog, L"[Diff] Added entries:");
        for (const auto& s : added) AppendLog(hLog, L"  + " + s);
    }
    if (!removed.empty()) {
        AppendLog(hLog, L"[Diff] Removed entries:");
        for (const auto& s : removed) AppendLog(hLog, L"  - " + s);
    }
}

static void ExportLogToFile(HWND hWnd, HWND hLog) {
    if (!hLog) return;

    // Get the log text
    int len = GetWindowTextLengthW(hLog);
    std::wstring text;
    text.resize(len);
    if (len > 0) {
        GetWindowTextW(hLog, text.data(), len + 1);
        // Adjust size because std::wstring::data() doesn't set null terminator count
        text.resize(wcslen(text.c_str()));
    }

    IFileSaveDialog* pDlg = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_FileSaveDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pDlg));
    if (FAILED(hr)) return;

    COMDLG_FILTERSPEC filters[] = {
        { L"Text Files (*.txt)", L"*.txt" },
        { L"All Files (*.*)", L"*.*" }
    };
    pDlg->SetFileTypes(ARRAYSIZE(filters), filters);
    pDlg->SetDefaultExtension(L"txt");
    pDlg->SetTitle(L"Export Log");

    hr = pDlg->Show(hWnd);
    if (FAILED(hr)) {
        pDlg->Release();
        return;
    }

    IShellItem* pItem = nullptr;
    hr = pDlg->GetResult(&pItem);
    if (FAILED(hr)) {
        pDlg->Release();
        return;
    }

    PWSTR psz = nullptr;
    hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &psz);
    if (SUCCEEDED(hr) && psz) {
        // Write UTF-16LE with BOM
        HANDLE hFile = CreateFileW(psz, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            const WCHAR bom = 0xFEFF;
            DWORD written = 0;
            WriteFile(hFile, &bom, sizeof(bom), &written, nullptr);
            if (!text.empty()) {
                WriteFile(hFile, text.c_str(), static_cast<DWORD>(text.size() * sizeof(wchar_t)), &written, nullptr);
            }
            CloseHandle(hFile);
        }
        CoTaskMemFree(psz);
    }
    pItem->Release();
    pDlg->Release();
}

static void AppendLastError(HWND hLog, const std::wstring& prefix, DWORD gle) {
    LPWSTR msgBuf = nullptr;
    DWORD len = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                               nullptr, gle, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                               (LPWSTR)&msgBuf, 0, nullptr);
    if (len && msgBuf) {
        std::wstring msg(msgBuf, len);
        // Trim trailing newlines
        while (!msg.empty() && (msg.back() == L'\r' || msg.back() == L'\n')) msg.pop_back();
        AppendLog(hLog, prefix + L" GLE=" + std::to_wstring(gle) + L" (" + msg + L")");
        LocalFree(msgBuf);
    } else {
        AppendLog(hLog, prefix + L" GLE=" + std::to_wstring(gle));
    }
}

static void DiagnoseRegistrationFailure(HWND hWnd, HWND hLog, const std::wstring& dllPath, bool isUnregister) {
    if (!hLog || dllPath.empty()) return;

    // 1) Basic file checks
    DWORD attr = GetFileAttributesW(dllPath.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) {
        DWORD gle = GetLastError();
        AppendLastError(hLog, L"[Detail] DLL not accessible.", gle);
        return;
    } else {
        WIN32_FILE_ATTRIBUTE_DATA fad{};
        if (GetFileAttributesExW(dllPath.c_str(), GetFileExInfoStandard, &fad)) {
            AppendLog(hLog, L"[Detail] DLL size: " + std::to_wstring(((ULONGLONG)fad.nFileSizeHigh << 32) | fad.nFileSizeLow) + L" bytes");
        }
    }

    // 2) Try to load the DLL (normal load to exercise dependencies)
    HMODULE mod = LoadLibraryExW(dllPath.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!mod) {
        DWORD gle = GetLastError();
        AppendLastError(hLog, L"[Detail] LoadLibraryEx failed.", gle);
    } else {
        // 3) Check expected export exists
        const char* exportName = isUnregister ? "DllUnregisterServer" : "DllRegisterServer";
        FARPROC proc = GetProcAddress(mod, exportName);
        if (!proc) {
            AppendLog(hLog, L"[Detail] Export '" + std::wstring(exportName, exportName + strlen(exportName)) + L"' not found.");
            // Also check alternative 'DllInstall'
            FARPROC di = GetProcAddress(mod, "DllInstall");
            if (di) {
                AppendLog(hLog, L"[Detail] 'DllInstall' export is present; registration may rely on installer context.");
            }
        } else {
            AppendLog(hLog, L"[Detail] Export '" + std::wstring(exportName, exportName + strlen(exportName)) + L"' is present.");
        }
        FreeLibrary(mod);
    }

    // 4) Dependency resolution (report any that cannot be found via loader search)
    std::vector<std::wstring> names;
    std::wstring err;
    if (peutils::GetImportedDllNames(dllPath, names, err)) {
        int missing = 0;
        std::wstring primaryDir = DirName(dllPath);
        for (const auto& name : names) {
            std::wstring resolved = ResolvePathWithGetModuleFileName(name, primaryDir);
            if (resolved.empty()) {
                if (missing == 0) AppendLog(hLog, L"[Detail] Missing dependency DLLs (not resolved by loader):");
                AppendLog(hLog, L"          - " + name);
                ++missing;
            }
        }
        if (missing == 0) {
            AppendLog(hLog, L"[Detail] All imported DLLs resolved via loader search.");
        }
    } else {
        AppendLog(hLog, L"[Detail] Could not enumerate imports: " + err);
    }

    // 5) UAC hint already logged elsewhere; add concise reminder
    AppendLog(hLog, L"[Hint] If access denied persists, try 'Register (Elevated)' or run the app elevated.");
}

static void PopulateDependencies(HWND hWnd, AppState* app) {
    if (!app || app->selectedDllPath.empty()) return;

    ClearList(app->hList);

    std::vector<std::wstring> names;
    std::wstring err;
    if (!peutils::GetImportedDllNames(app->selectedDllPath, names, err)) {
        AppendLog(app->hLog, L"[Error] Reading imports failed: " + err);
        return;
    }
    std::wstring primaryDir = DirName(app->selectedDllPath);

    int row = 0;
    for (const auto& dllName : names) {
        std::wstring resolved = ResolvePathWithGetModuleFileName(dllName, primaryDir);
        LVITEMW item{};
        item.mask = LVIF_TEXT;
        item.iItem = row;
        item.iSubItem = 0;
        item.pszText = const_cast<LPWSTR>(dllName.c_str());
        int idx = ListView_InsertItem(app->hList, &item);
        if (idx >= 0) {
            std::wstring shown = resolved.empty() ? L"(Not Found)" : resolved;
            ListView_SetItemText(app->hList, idx, 1, const_cast<LPWSTR>(shown.c_str()));
            // Description (from version resource)
            std::wstring desc;
            std::wstring company;
            if (!resolved.empty()) {
                desc = GetFileDescription(resolved);
                company = GetFileCompanyName(resolved);
            }
            ListView_SetItemText(app->hList, idx, 2, const_cast<LPWSTR>((desc.empty() ? L"" : desc).c_str()));
            ListView_SetItemText(app->hList, idx, 3, const_cast<LPWSTR>((company.empty() ? L"" : company).c_str()));
            ++row;
        }
    }

    // Auto-size second column to fit content up to a reasonable width
    ListView_SetColumnWidth(app->hList, 0, 220);
    ListView_SetColumnWidth(app->hList, 1, LVSCW_AUTOSIZE_USEHEADER);
    ListView_SetColumnWidth(app->hList, 2, LVSCW_AUTOSIZE_USEHEADER);
    ListView_SetColumnWidth(app->hList, 3, LVSCW_AUTOSIZE_USEHEADER);

    std::wstringstream ss;
    ss << L"[Info] Parsed " << names.size() << L" imported DLL(s).";
    AppendLog(app->hLog, ss.str());
}

static std::wstring TimeStamp() {
    SYSTEMTIME st{};
    GetLocalTime(&st);
    wchar_t buf[64];
    swprintf(buf, 64, L"%04u-%02u-%02u %02u:%02u:%02u",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

static void RegisterSelectedDll(HWND hWnd, AppState* app) {
    if (!app || app->selectedDllPath.empty()) {
        AppendLog(((AppState*)GetWindowLongPtrW(hWnd, GWLP_USERDATA))->hLog, L"[Error] No DLL selected.");
        return;
    }

    std::wstring note, err;
    std::wstring regsvr = peutils::GetRegsvr32PathForTarget(app->selectedDllMachine, note, err);
    if (regsvr.empty()) {
        AppendLog(app->hLog, L"[Error] regsvr32 path selection failed: " + err);
        return;
    }

    AppendLog(app->hLog, L"[Info] " + note);
    // Take registry snapshot (before)
    app->regSnapBefore.clear();
    TakeRegistrySnapshotForDll(app->selectedDllPath, app->regSnapBefore);

    std::wstring cmdline = L"\"" + regsvr + L"\" /s \"" + app->selectedDllPath + L"\"";
    AppendLog(app->hLog, L"[Start] " + TimeStamp() + L" Running: " + cmdline);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    // Application name should be the path; command line contains the full quoted path + args
    std::wstring mutableCmd = cmdline; // CreateProcess requires mutable buffer
    BOOL ok = CreateProcessW(
        regsvr.c_str(),
        mutableCmd.data(),
        nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW,
        nullptr, nullptr,
        &si, &pi
    );
    if (!ok) {
        DWORD gle = GetLastError();
        std::wstringstream ss;
        ss << L"[Error] CreateProcess failed. GLE=" << gle;
        AppendLog(app->hLog, ss.str());
        if (gle == ERROR_ELEVATION_REQUIRED || gle == ERROR_ACCESS_DENIED) {
            AppendLog(app->hLog, L"[Hint] Try 'Register (Elevated)'.");
        }
        return;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    std::wstringstream ss;
    ss << L"[End] " << TimeStamp() << L" ExitCode=" << exitCode;
    AppendLog(app->hLog, ss.str());

    if (exitCode == 0) {
        AppendLog(app->hLog, L"[Success] Registration completed.");
        AppendLog(app->hLog, L"[Info] Scanning registry for entries referencing this DLL...");
        ListRegistryWritesForDll(app->selectedDllPath, app->hLog);
        ListOfficeLoadBehaviorForDll(app->selectedDllPath, app->hLog);

        // Take registry snapshot (after)
        app->regSnapAfter.clear();
        TakeRegistrySnapshotForDll(app->selectedDllPath, app->regSnapAfter);
        AppendLog(app->hLog, L"[Info] Captured registry snapshots (before/after). Use 'Registry Update' to view diff.");
    } else {
        AppendLog(app->hLog, L"[Warning] Registration failed or returned non-zero.");
        AppendLog(app->hLog, L"          If this is due to permissions, try running the app elevated.");
        DiagnoseRegistrationFailure(hWnd, app->hLog, app->selectedDllPath, /*isUnregister=*/false);
    }
}

static void RegisterSelectedDllElevated(HWND hWnd, AppState* app) {
    if (!app || app->selectedDllPath.empty()) {
        AppendLog(((AppState*)GetWindowLongPtrW(hWnd, GWLP_USERDATA))->hLog, L"[Error] No DLL selected.");
        return;
    }

    std::wstring note, err;
    std::wstring regsvr = peutils::GetRegsvr32PathForTarget(app->selectedDllMachine, note, err);
    if (regsvr.empty()) {
        AppendLog(app->hLog, L"[Error] regsvr32 path selection failed: " + err);
        return;
    }

    AppendLog(app->hLog, L"[Info] (Elevated) " + note);
    // Take registry snapshot (before)
    app->regSnapBefore.clear();
    TakeRegistrySnapshotForDll(app->selectedDllPath, app->regSnapBefore);

    std::wstring params = L"/s \"" + app->selectedDllPath + L"\"";

    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.hwnd = hWnd;
    sei.lpVerb = L"runas";
    sei.lpFile = regsvr.c_str();
    sei.lpParameters = params.c_str();
    sei.nShow = SW_HIDE;

    AppendLog(app->hLog, L"[Start] " + TimeStamp() + L" Elevating and running: \"" + regsvr + L"\" " + params);

    if (!ShellExecuteExW(&sei)) {
        DWORD gle = GetLastError();
        std::wstringstream ss;
        ss << L"[Error] ShellExecuteEx (runas) failed. GLE=" << gle;
        AppendLog(app->hLog, ss.str());
        return;
    }

    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, INFINITE);
        DWORD exitCode = 0;
        GetExitCodeProcess(sei.hProcess, &exitCode);
        CloseHandle(sei.hProcess);

        std::wstringstream ss;
        ss << L"[End] " << TimeStamp() << L" (Elevated) ExitCode=" << exitCode;
        AppendLog(app->hLog, ss.str());

        if (exitCode == 0) {
            AppendLog(app->hLog, L"[Success] Registration completed (elevated).");
            AppendLog(app->hLog, L"[Info] Scanning registry for entries referencing this DLL...");
            ListRegistryWritesForDll(app->selectedDllPath, app->hLog);
            ListOfficeLoadBehaviorForDll(app->selectedDllPath, app->hLog);

            // Take registry snapshot (after)
            app->regSnapAfter.clear();
            TakeRegistrySnapshotForDll(app->selectedDllPath, app->regSnapAfter);
            AppendLog(app->hLog, L"[Info] Captured registry snapshots (before/after). Use 'Registry Update' to view diff.");
        } else {
            AppendLog(app->hLog, L"[Warning] Registration failed or returned non-zero (elevated).");
            DiagnoseRegistrationFailure(hWnd, app->hLog, app->selectedDllPath, /*isUnregister=*/false);
        }
    } else {
        AppendLog(app->hLog, L"[Info] No process handle returned from ShellExecuteEx.");
    }
}

static bool ShowOpenDllDialog(std::wstring& outPath) {
    outPath.clear();
    IFileOpenDialog* pDlg = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pDlg));
    if (FAILED(hr)) return false;

    COMDLG_FILTERSPEC filters[] = {
        { L"DLL/OCX files", L"*.dll;*.ocx" },
        { L"All files",     L"*.*" }
    };
    pDlg->SetFileTypes(ARRAYSIZE(filters), filters);
    pDlg->SetDefaultExtension(L"dll");
    pDlg->SetTitle(L"Select a DLL to inspect");

    hr = pDlg->Show(nullptr);
    if (FAILED(hr)) {
        pDlg->Release();
        return false;
    }

    IShellItem* pItem = nullptr;
    hr = pDlg->GetResult(&pItem);
    if (FAILED(hr)) {
        pDlg->Release();
        return false;
    }

    PWSTR psz = nullptr;
    hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &psz);
    if (SUCCEEDED(hr) && psz) {
        outPath = psz;
        CoTaskMemFree(psz);
    }
    pItem->Release();
    pDlg->Release();
    return !outPath.empty();
}

static void LayoutControls(HWND hWnd, AppState* app, int cx, int cy) {
    const int pad = 8;
    const int btnH = 28;
    const int btnW = 140;

    // Buttons row at top
    int x = pad;
    int y = pad;
    MoveWindow(app->hOpenBtn, x, y, btnW, btnH, TRUE);
    x += btnW + pad;
    MoveWindow(app->hRegBtn, x, y, btnW, btnH, TRUE);
    x += btnW + pad;
    MoveWindow(app->hRegElevBtn, x, y, btnW, btnH, TRUE);
    x += btnW + pad;
    MoveWindow(app->hUnregBtn, x, y, btnW, btnH, TRUE);
    x += btnW + pad;
    MoveWindow(app->hClearLogBtn, x, y, btnW, btnH, TRUE);
    x += btnW + pad;
    MoveWindow(app->hRegDiffBtn, x, y, btnW, btnH, TRUE);
    x += btnW + pad;
    MoveWindow(app->hExportLogBtn, x, y, btnW, btnH, TRUE);

    // List occupies upper half area
    int topAreaY = y + btnH + pad;
    int listH = (cy - topAreaY - pad) / 2;
    if (listH < 100) listH = 100;
    MoveWindow(app->hList, pad, topAreaY, cx - 2 * pad, listH, TRUE);

    // Log occupies remaining space
    int logY = topAreaY + listH + pad;
    int logH = cy - logY - pad;
    if (logH < 60) logH = 60;
    MoveWindow(app->hLog, pad, logY, cx - 2 * pad, logH, TRUE);
}

static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    AppState* app = reinterpret_cast<AppState*>(GetWindowLongPtrW(hWnd, GWLP_USERDATA));
    switch (msg) {
    case WM_CREATE: {
        INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_LISTVIEW_CLASSES };
        InitCommonControlsEx(&icc);

        app = new AppState();
        SetWindowLongPtrW(hWnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(app));

        app->hOpenBtn = CreateWindowW(L"BUTTON", L"Open DLL...",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            0, 0, 0, 0, hWnd, (HMENU)IDC_OPEN_BTN, GetModuleHandleW(nullptr), nullptr);

        app->hRegBtn = CreateWindowW(L"BUTTON", L"Register DLL",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_DISABLED,
            0, 0, 0, 0, hWnd, (HMENU)IDC_REG_BTN, GetModuleHandleW(nullptr), nullptr);
        app->hRegElevBtn = CreateWindowW(L"BUTTON", L"Register (Elevated)",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_DISABLED,
            0, 0, 0, 0, hWnd, (HMENU)IDC_REG_ELEV, GetModuleHandleW(nullptr), nullptr);

        app->hUnregBtn = CreateWindowW(L"BUTTON", L"Unregister DLL",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_DISABLED,
            0, 0, 0, 0, hWnd, (HMENU)IDC_UNREG, GetModuleHandleW(nullptr), nullptr);

        app->hClearLogBtn = CreateWindowW(L"BUTTON", L"Clear Log",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            0, 0, 0, 0, hWnd, (HMENU)IDC_CLEAR_LOG, GetModuleHandleW(nullptr), nullptr);

        app->hRegDiffBtn = CreateWindowW(L"BUTTON", L"Registry Update",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            0, 0, 0, 0, hWnd, (HMENU)IDC_REG_DIFF, GetModuleHandleW(nullptr), nullptr);

        app->hExportLogBtn = CreateWindowW(L"BUTTON", L"Export Log...",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            0, 0, 0, 0, hWnd, (HMENU)IDC_EXPORT_LOG, GetModuleHandleW(nullptr), nullptr);

        app->hList = CreateWindowW(WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | WS_TABSTOP | WS_BORDER,
            0, 0, 0, 0, hWnd, (HMENU)IDC_LIST, GetModuleHandleW(nullptr), nullptr);

        app->hLog = CreateWindowW(L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL | ES_READONLY | WS_BORDER,
            0, 0, 0, 0, hWnd, (HMENU)IDC_LOG, GetModuleHandleW(nullptr), nullptr);

        InitListViewColumns(app->hList);
        AppendLog(app->hLog, L"Dependency Explorer ready.");
        // Report executable path and directory using GetModuleFileNameW
        {
            wchar_t exePath[MAX_PATH];
            DWORD n = GetModuleFileNameW(nullptr, exePath, MAX_PATH);
            if (n > 0 && n < MAX_PATH) {
                std::wstring exe(exePath, n);
                AppendLog(app->hLog, L"[Info] Executable: " + exe);
                std::wstring exeDir = DirName(exe);
                if (!exeDir.empty()) {
                    AppendLog(app->hLog, L"[Info] Executable Dir: " + exeDir);
                }
            } else {
                AppendLog(app->hLog, L"[Warning] Unable to determine executable path.");
            }
        }
        return 0;
    }
    case WM_SIZE: {
        if (app) {
            int cx = LOWORD(lParam);
            int cy = HIWORD(lParam);
            LayoutControls(hWnd, app, cx, cy);
        }
        return 0;
    }
    case WM_COMMAND: {
        if (!app) break;
        switch (LOWORD(wParam)) {
        case IDC_OPEN_BTN: {
            std::wstring path;
            if (ShowOpenDllDialog(path)) {
                app->selectedDllPath = path;

                // Determine machine
                peutils::MachineType mt = peutils::MachineType::Unknown;
                std::wstring err;
                if (!peutils::GetDllMachineType(app->selectedDllPath, mt, err)) {
                    AppendLog(app->hLog, L"[Error] Failed to read DLL machine type: " + err);
                    EnableWindow(app->hRegBtn, FALSE);
                } else {
                    app->selectedDllMachine = mt;
                    std::wstring mstr = (mt == peutils::MachineType::x64) ? L"x64" :
                                        (mt == peutils::MachineType::x86) ? L"x86" : L"Unknown";
                    AppendLog(app->hLog, L"[Info] Selected: " + app->selectedDllPath + L" (" + mstr + L")");
                    EnableWindow(app->hRegBtn, mt != peutils::MachineType::Unknown);
                    EnableWindow(app->hRegElevBtn, mt != peutils::MachineType::Unknown);
                    EnableWindow(app->hUnregBtn, mt != peutils::MachineType::Unknown);
                }
                PopulateDependencies(hWnd, app);
            }
            return 0;
        }
        case IDC_REG_BTN: {
            RegisterSelectedDll(hWnd, app);
            return 0;
        }
        case IDC_REG_ELEV: {
            RegisterSelectedDllElevated(hWnd, app);
            return 0;
        }
        case IDC_CLEAR_LOG: {
            // Temporarily disable read-only to clear the log edit box
            SendMessageW(app->hLog, EM_SETREADONLY, FALSE, 0);
            SetWindowTextW(app->hLog, L"");
            SendMessageW(app->hLog, EM_SETREADONLY, TRUE, 0);
            return 0;
        }
        case IDC_UNREG: {
            if (!app->selectedDllPath.empty()) {
                std::wstring note, err;
                std::wstring regsvr = peutils::GetRegsvr32PathForTarget(app->selectedDllMachine, note, err);
                if (regsvr.empty()) {
                    AppendLog(app->hLog, L"[Error] regsvr32 path selection failed: " + err);
                    return 0;
                }
                AppendLog(app->hLog, L"[Info] " + note);
                // Snapshot before
                app->regSnapBefore.clear();
                TakeRegistrySnapshotForDll(app->selectedDllPath, app->regSnapBefore);

                std::wstring cmdline = L"\"" + regsvr + L"\" /u /s \"" + app->selectedDllPath + L"\"";
                AppendLog(app->hLog, L"[Start] " + TimeStamp() + L" Running: " + cmdline);

                STARTUPINFOW si{}; si.cb = sizeof(si);
                PROCESS_INFORMATION pi{};
                std::wstring mutableCmd = cmdline;
                BOOL ok = CreateProcessW(
                    regsvr.c_str(),
                    mutableCmd.data(),
                    nullptr, nullptr, FALSE,
                    CREATE_NO_WINDOW,
                    nullptr, nullptr,
                    &si, &pi
                );
                if (!ok) {
                    DWORD gle = GetLastError();
                    std::wstringstream sse;
                    sse << L"[Error] CreateProcess (unregister) failed. GLE=" << gle;
                    AppendLog(app->hLog, sse.str());
                    return 0;
                }
                WaitForSingleObject(pi.hProcess, INFINITE);
                DWORD exitCode = 0;
                GetExitCodeProcess(pi.hProcess, &exitCode);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);

                std::wstringstream sse;
                sse << L"[End] " << TimeStamp() << L" Unregister ExitCode=" << exitCode;
                AppendLog(app->hLog, sse.str());

                if (exitCode == 0) {
                    AppendLog(app->hLog, L"[Success] Unregistration completed.");
                    // Snapshot after
                    app->regSnapAfter.clear();
                    TakeRegistrySnapshotForDll(app->selectedDllPath, app->regSnapAfter);
                    AppendLog(app->hLog, L"[Info] Captured registry snapshots (before/after). Use 'Registry Update' to view diff.");
                } else {
                    AppendLog(app->hLog, L"[Warning] Unregistration returned non-zero.");
                    DiagnoseRegistrationFailure(hWnd, app->hLog, app->selectedDllPath, /*isUnregister=*/true);
                }
            } else {
                AppendLog(app->hLog, L"[Error] No DLL selected.");
            }
            return 0;
        }
        case IDC_REG_DIFF: {
            if (!app->regSnapBefore.empty() || !app->regSnapAfter.empty()) {
                AppendLog(app->hLog, L"[Info] Computing registry diff (before vs after)...");
                ComputeAndLogRegistryDiff(app->hLog, app->regSnapBefore, app->regSnapAfter);
            } else {
                AppendLog(app->hLog, L"[Info] No snapshots available. Perform a registration first.");
            }
            return 0;
        }
        case IDC_EXPORT_LOG: {
            ExportLogToFile(hWnd, app->hLog);
            return 0;
        }
        default: break;
        }
        break;
    }
    case WM_DESTROY: {
        if (app) {
            delete app;
            SetWindowLongPtrW(hWnd, GWLP_USERDATA, 0);
        }
        PostQuitMessage(0);
        return 0;
    }
    default: break;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

int APIENTRY wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nCmdShow) {
    // Initialize COM for file picker
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    bool comInit = SUCCEEDED(hr);

    WNDCLASSW wc{};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wc.lpszClassName = kClassName;

    if (!RegisterClassW(&wc)) {
        if (comInit) CoUninitialize();
        return 0;
    }

    HWND hWnd = CreateWindowExW(0, kClassName, L"Dependency Explorer - DLL Dependencies and Registration",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1000, 700,
        nullptr, nullptr, hInst, nullptr);
    if (!hWnd) {
        if (comInit) CoUninitialize();
        return 0;
    }

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    if (comInit) CoUninitialize();
    return (int)msg.wParam;
}
