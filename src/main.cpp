#include <windows.h>
#include <commctrl.h>
#include <shobjidl.h> // IFileOpenDialog
#include <shellapi.h> // ShellExecuteExW
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <winver.h>
#include "pe_utils.h"

#pragma comment(lib, "Comctl32.lib")
#pragma comment(lib, "Version.lib")

/* Control IDs */
#define IDC_OPEN_BTN     1001
#define IDC_REG_BTN      1002
#define IDC_LIST         1003
#define IDC_LOG          1004
#define IDC_REG_ELEV     1005

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
    } else {
        AppendLog(app->hLog, L"[Warning] Registration failed or returned non-zero.");
        AppendLog(app->hLog, L"          If this is due to permissions, try running the app elevated.");
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
        } else {
            AppendLog(app->hLog, L"[Warning] Registration failed or returned non-zero (elevated).");
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
