#include "pe_utils.h"

#include <windows.h>
#include <string>
#include <vector>
#include <memory>
#include <cstdio>

namespace peutils {

// RAII helpers for file mapping
struct FileMapping {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMap = nullptr;
    BYTE*  base = nullptr;
    size_t size = 0;

    ~FileMapping() {
        if (base) UnmapViewOfFile(base);
        if (hMap) CloseHandle(hMap);
        if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    }
};

static bool MapFileRead(const std::wstring& path, FileMapping& outMap, std::wstring& outError) {
    outMap = {};
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        outError = L"CreateFileW failed: " + std::to_wstring(GetLastError());
        return false;
    }
    LARGE_INTEGER li{};
    if (!GetFileSizeEx(hFile, &li)) {
        outError = L"GetFileSizeEx failed: " + std::to_wstring(GetLastError());
        CloseHandle(hFile);
        return false;
    }
    if (li.QuadPart <= 0) {
        outError = L"Empty file.";
        CloseHandle(hFile);
        return false;
    }
    HANDLE hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMap) {
        outError = L"CreateFileMappingW failed: " + std::to_wstring(GetLastError());
        CloseHandle(hFile);
        return false;
    }
    BYTE* base = (BYTE*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!base) {
        outError = L"MapViewOfFile failed: " + std::to_wstring(GetLastError());
        CloseHandle(hMap);
        CloseHandle(hFile);
        return false;
    }
    outMap.hFile = hFile;
    outMap.hMap = hMap;
    outMap.base = base;
    outMap.size = static_cast<size_t>(li.QuadPart);
    return true;
}

struct PeView {
    IMAGE_DOS_HEADER* dos = nullptr;
    BYTE* nt_any = nullptr; // points to IMAGE_NT_HEADERS{32,64}
    WORD  magic = 0;        // OptionalHeader.Magic
    IMAGE_FILE_HEADER* fileHeader = nullptr;
    IMAGE_DATA_DIRECTORY* dataDir = nullptr;
    WORD numSections = 0;
    IMAGE_SECTION_HEADER* firstSection = nullptr;
};

static bool ParsePeHeaders(BYTE* base, size_t size, PeView& out, std::wstring& outError) {
    if (size < sizeof(IMAGE_DOS_HEADER)) {
        outError = L"File too small for DOS header.";
        return false;
    }
    auto dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        outError = L"Missing MZ signature.";
        return false;
    }
    if ((size_t)dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) > size) {
        outError = L"Invalid e_lfanew.";
        return false;
    }
    BYTE* nt = base + dos->e_lfanew;
    DWORD sig = *(DWORD*)nt;
    if (sig != IMAGE_NT_SIGNATURE) {
        outError = L"Missing PE signature.";
        return false;
    }
    auto fileHeader = (IMAGE_FILE_HEADER*)(nt + sizeof(DWORD));
    BYTE* optHeaderAny = (BYTE*)(fileHeader + 1);
    if ((size_t)(optHeaderAny - base) + fileHeader->SizeOfOptionalHeader > size) {
        outError = L"Optional header extends beyond file.";
        return false;
    }
    WORD magic = *(WORD*)optHeaderAny;
    IMAGE_DATA_DIRECTORY* dataDir = nullptr;
    IMAGE_SECTION_HEADER* firstSection = nullptr;

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        auto nt64 = (IMAGE_NT_HEADERS64*)nt;
        dataDir = (IMAGE_DATA_DIRECTORY*)nt64->OptionalHeader.DataDirectory;
        firstSection = (IMAGE_SECTION_HEADER*)((BYTE*)&nt64->OptionalHeader + nt64->FileHeader.SizeOfOptionalHeader);
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        auto nt32 = (IMAGE_NT_HEADERS32*)nt;
        dataDir = (IMAGE_DATA_DIRECTORY*)nt32->OptionalHeader.DataDirectory;
        firstSection = (IMAGE_SECTION_HEADER*)((BYTE*)&nt32->OptionalHeader + nt32->FileHeader.SizeOfOptionalHeader);
    } else {
        outError = L"Unknown optional header magic.";
        return false;
    }

    if ((BYTE*)firstSection + fileHeader->NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > base + size) {
        outError = L"Section headers extend beyond file.";
        return false;
    }

    out.dos = dos;
    out.nt_any = nt;
    out.magic = magic;
    out.fileHeader = fileHeader;
    out.dataDir = dataDir;
    out.numSections = fileHeader->NumberOfSections;
    out.firstSection = firstSection;
    return true;
}

static BYTE* RvaToPtr(DWORD rva, const PeView& pe, BYTE* base, size_t size) {
    // Find the section that contains the RVA
    for (WORD i = 0; i < pe.numSections; ++i) {
        const IMAGE_SECTION_HEADER& sec = pe.firstSection[i];
        DWORD sectVA = sec.VirtualAddress;
        DWORD sectSize = sec.Misc.VirtualSize ? sec.Misc.VirtualSize : sec.SizeOfRawData;
        if (rva >= sectVA && rva < sectVA + sectSize) {
            DWORD delta = rva - sectVA;
            DWORD fileOffset = sec.PointerToRawData + delta;
            if (fileOffset >= size) return nullptr;
            return base + fileOffset;
        }
    }
    // Also allow the case where sections are not used (rare)
    if (rva < size) return base + rva;
    return nullptr;
}

bool GetDllMachineType(const std::wstring& dllPath, MachineType& outType, std::wstring& outError) {
    outType = MachineType::Unknown;

    HANDLE hFile = CreateFileW(dllPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        outError = L"CreateFileW failed: " + std::to_wstring(GetLastError());
        return false;
    }

    IMAGE_DOS_HEADER dos{};
    DWORD bytes = 0;
    if (!ReadFile(hFile, &dos, sizeof(dos), &bytes, nullptr) || bytes != sizeof(dos)) {
        outError = L"Read DOS header failed: " + std::to_wstring(GetLastError());
        CloseHandle(hFile);
        return false;
    }
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        outError = L"Not a PE file (MZ missing).";
        CloseHandle(hFile);
        return false;
    }

    if (SetFilePointer(hFile, dos.e_lfanew, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR) {
        outError = L"SetFilePointer to NT headers failed: " + std::to_wstring(GetLastError());
        CloseHandle(hFile);
        return false;
    }

    DWORD sig = 0;
    if (!ReadFile(hFile, &sig, sizeof(sig), &bytes, nullptr) || bytes != sizeof(sig) || sig != IMAGE_NT_SIGNATURE) {
        outError = L"Read PE signature failed.";
        CloseHandle(hFile);
        return false;
    }

    IMAGE_FILE_HEADER fh{};
    if (!ReadFile(hFile, &fh, sizeof(fh), &bytes, nullptr) || bytes != sizeof(fh)) {
        outError = L"Read file header failed.";
        CloseHandle(hFile);
        return false;
    }

    CloseHandle(hFile);

    if (fh.Machine == IMAGE_FILE_MACHINE_AMD64) {
        outType = MachineType::x64;
    } else if (fh.Machine == IMAGE_FILE_MACHINE_I386) {
        outType = MachineType::x86;
    } else {
        outType = MachineType::Unknown;
    }
    return true;
}

bool GetImportedDllNames(const std::wstring& dllPath, std::vector<std::wstring>& outDllNames, std::wstring& outError) {
    outDllNames.clear();

    FileMapping map;
    if (!MapFileRead(dllPath, map, outError)) {
        return false;
    }

    PeView pe{};
    if (!ParsePeHeaders(map.base, map.size, pe, outError)) {
        return false;
    }

    const IMAGE_DATA_DIRECTORY& impDir = pe.dataDir[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.VirtualAddress == 0 || impDir.Size == 0) {
        // No imports: success with empty list
        return true;
    }

    auto impDesc = (IMAGE_IMPORT_DESCRIPTOR*)RvaToPtr(impDir.VirtualAddress, pe, map.base, map.size);
    if (!impDesc) {
        outError = L"Failed to map import directory RVA.";
        return false;
    }

    // Iterate import descriptors until zero entry
    for (; impDesc->Name != 0; ++impDesc) {
        char* nameAnsi = (char*)RvaToPtr(impDesc->Name, pe, map.base, map.size);
        if (!nameAnsi) {
            // Skip malformed entry
            continue;
        }
        // Convert ANSI to wide
        int len = MultiByteToWideChar(CP_ACP, 0, nameAnsi, -1, nullptr, 0);
        if (len <= 0) continue;
        std::wstring wname(len - 1, L'\0');
        MultiByteToWideChar(CP_ACP, 0, nameAnsi, -1, &wname[0], len);
        outDllNames.push_back(wname);
    }

    return true;
}

std::wstring ResolveDllPath(const std::wstring& dllName, const std::wstring& primaryDir) {
    DWORD needed = SearchPathW(primaryDir.empty() ? nullptr : primaryDir.c_str(),
                               dllName.c_str(),
                               nullptr,
                               0,
                               nullptr,
                               nullptr);
    if (needed == 0) {
        return L"";
    }
    std::wstring buffer;
    buffer.resize(needed);
    DWORD written = SearchPathW(primaryDir.empty() ? nullptr : primaryDir.c_str(),
                                dllName.c_str(),
                                nullptr,
                                needed,
                                &buffer[0],
                                nullptr);
    if (written == 0) {
        return L"";
    }
    // Remove trailing null inserted by API
    if (!buffer.empty() && buffer.back() == L'\0') buffer.pop_back();
    return buffer;
}

bool IsProcess64Bit() {
#if defined(_WIN64)
    return true;
#else
    // Try IsWow64Process2 (Windows 10)
    typedef BOOL (WINAPI *LPFN_IsWow64Process2)(HANDLE, USHORT*, USHORT*);
    HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
    if (hKernel) {
        auto fn = (LPFN_IsWow64Process2)GetProcAddress(hKernel, "IsWow64Process2");
        if (fn) {
            USHORT processMachine = 0, nativeMachine = 0;
            if (fn(GetCurrentProcess(), &processMachine, &nativeMachine)) {
                // If process machine is 0 => not Wow64 => same as native. If native is 0x8664 => 64-bit OS.
                // Since we're a 32-bit process (compile-time), process is not 64-bit.
                return false;
            }
        }
    }
    return false;
#endif
}

bool IsOS64Bit() {
#if defined(_WIN64)
    return true;
#else
    // Try IsWow64Process2 first
    typedef BOOL (WINAPI *LPFN_IsWow64Process2)(HANDLE, USHORT*, USHORT*);
    HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
    if (hKernel) {
        auto fn2 = (LPFN_IsWow64Process2)GetProcAddress(hKernel, "IsWow64Process2");
        if (fn2) {
            USHORT processMachine = 0, nativeMachine = 0;
            if (fn2(GetCurrentProcess(), &processMachine, &nativeMachine)) {
                return nativeMachine == IMAGE_FILE_MACHINE_AMD64 || nativeMachine == IMAGE_FILE_MACHINE_ARM64;
            }
        }
    }
    // Fallback to IsWow64Process
    typedef BOOL (WINAPI *LPFN_IsWow64Process)(HANDLE, PBOOL);
    auto fn = (LPFN_IsWow64Process)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process");
    BOOL wow64 = FALSE;
    if (fn && fn(GetCurrentProcess(), &wow64)) {
        return wow64 ? true : false;
    }
    return false;
#endif
}

std::wstring GetWindowsDir() {
    UINT needed = GetWindowsDirectoryW(nullptr, 0);
    if (needed == 0) return L"";
    std::wstring dir;
    dir.resize(needed);
    UINT written = GetWindowsDirectoryW(&dir[0], needed);
    if (written == 0) return L"";
    if (!dir.empty() && dir.back() == L'\0') dir.pop_back();
    return dir;
}

static bool FileExists(const std::wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES) && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

std::wstring GetRegsvr32PathForTarget(MachineType target, std::wstring& outNote, std::wstring& outError) {
    outNote.clear();
    outError.clear();
    std::wstring winDir = GetWindowsDir();
    if (winDir.empty()) {
        outError = L"Failed to obtain Windows directory.";
        return L"";
    }

    bool os64 = IsOS64Bit();
    bool proc64 = IsProcess64Bit();

    std::wstring path;
    if (target == MachineType::x64) {
        if (!os64) {
            outError = L"Target DLL is x64 but OS is 32-bit.";
            return L"";
        }
        if (proc64) {
            path = winDir + L"\\System32\\regsvr32.exe";
            outNote = L"Using 64-bit regsvr32 from System32 (64-bit process).";
        } else {
            // 32-bit process on 64-bit OS needs Sysnative to reach 64-bit System32
            path = winDir + L"\\Sysnative\\regsvr32.exe";
            outNote = L"Using 64-bit regsvr32 via Sysnative (32-bit process on 64-bit OS).";
        }
    } else if (target == MachineType::x86) {
        if (os64) {
            path = winDir + L"\\SysWOW64\\regsvr32.exe";
            outNote = L"Using 32-bit regsvr32 from SysWOW64 (64-bit OS).";
        } else {
            path = winDir + L"\\System32\\regsvr32.exe";
            outNote = L"Using 32-bit regsvr32 from System32 (32-bit OS).";
        }
    } else {
        outError = L"Unknown target machine type for regsvr32 selection.";
        return L"";
    }

    if (!FileExists(path)) {
        outError = L"regsvr32 not found at: " + path;
        return L"";
    }
    return path;
}

} // namespace peutils
