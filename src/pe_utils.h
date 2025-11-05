#pragma once

#include <windows.h>
#include <string>
#include <vector>

namespace peutils {

// Target machine/bitness of a DLL
enum class MachineType {
    x86,
    x64,
    Unknown
};

// Read the PE headers of the file at dllPath and return its machine type
bool GetDllMachineType(const std::wstring& dllPath, MachineType& outType, std::wstring& outError);

// Extract direct imported DLL names from the file's import table
// Returns true on success; on failure, outError is populated
bool GetImportedDllNames(const std::wstring& dllPath, std::vector<std::wstring>& outDllNames, std::wstring& outError);

// Resolve the actual path Windows would load for the given dllName,
// giving priority to the primaryDir (directory of the inspected DLL).
// Returns empty string if not found.
std::wstring ResolveDllPath(const std::wstring& dllName, const std::wstring& primaryDir);

// OS/process helpers
bool IsProcess64Bit();
bool IsOS64Bit();

// Retrieve Windows directory (e.g., C:\Windows). Returns empty on error.
std::wstring GetWindowsDir();

// Choose the correct full path to regsvr32.exe for the target DLL bitness.
// - For x64 targets on x64 OS:
//   * If process is 64-bit:   %SystemRoot%\System32\regsvr32.exe
//   * If process is 32-bit:   %SystemRoot%\Sysnative\regsvr32.exe
// - For x86 targets:
//   * On x64 OS:              %SystemRoot%\SysWOW64\regsvr32.exe
//   * On x86 OS:              %SystemRoot%\System32\regsvr32.exe
// Returns empty string on failure and sets outError.
std::wstring GetRegsvr32PathForTarget(MachineType target, std::wstring& outNote, std::wstring& outError);

} // namespace peutils
