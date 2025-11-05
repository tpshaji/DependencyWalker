# Dependency Explorer (Win32 GUI)
A small native Windows utility written in C++ that:
- Opens a DLL via a file picker
- Parses its import table and displays dependent DLLs
- Shows two columns: “DLL Name” and “Resolved Path” (the path Windows would load)
- Registers the selected DLL via regsvr32 with:
  - Register DLL (normal)
  - Register (Elevated) for admin-required scenarios
- Logs a detailed, verbose transcript (command, resolved regsvr32 path, bitness, exit code, timestamps)

Note: regsvr32 does not emit redirectable console output; the app provides its own verbose log.

## Features
- Safe PE parsing to list direct imported DLLs
- Dependency path resolution using SearchPathW giving priority to the DLL’s own folder
- Accurate regsvr32 path selection based on the DLL’s architecture and OS bitness:
  - x64 DLL on x64 OS:
    - 64-bit process: %SystemRoot%\System32\regsvr32.exe
    - 32-bit process: %SystemRoot%\Sysnative\regsvr32.exe
  - x86 DLL:
    - On x64 OS: %SystemRoot%\SysWOW64\regsvr32.exe
    - On x86 OS: %SystemRoot%\System32\regsvr32.exe
- “Register (Elevated)” uses ShellExecuteEx with verb=runas

## Build Prerequisites
- Windows 10/11
- CMake (3.20+) 
- Microsoft Visual Studio 2022 Build Tools (or full VS) with “C++ build tools” (VCTools) installed

If you don’t have the tools installed, you can install them using winget (recommended):

```
winget install -e --id Kitware.CMake --source winget --accept-source-agreements --accept-package-agreements
winget install -e --id Microsoft.VisualStudio.2022.BuildTools --source winget --accept-source-agreements --accept-package-agreements --override "--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --passive --norestart"
```

Alternatively with Chocolatey:
```
choco install cmake --installargs 'ADD_CMAKE_TO_PATH=System' -y
choco install visualstudio2022buildtools --package-parameters "--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --passive --norestart" -y
```

After installation, open a “x64 Native Tools Command Prompt for VS 2022” to ensure the MSVC environment is set.

## Build (Command Line)
Generate a Visual Studio solution and build:
```
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

This will produce the executable at:
```
build\bin\Release\DependencyExplorer.exe
```

If you prefer NMake (from a Developer Command Prompt with nmake in PATH):
```
cmake -S . -B build -G "NMake Makefiles"
cmake --build build --config Release
```

## Build (Visual Studio / VS Code)
- Visual Studio: Open the folder as a CMake project or use “Open CMake” and build the “Release” config.
- VS Code: Install the CMake Tools extension, configure a “Visual Studio 17 2022” kit, and build.

## Usage
1) Launch the app:
   - build\bin\Release\DependencyExplorer.exe
2) Click “Open DLL…” and select a .dll or .ocx file.
3) The ListView shows:
   - DLL Name
   - Resolved Path (absolute path found by Windows search order; “(Not Found)” if missing)
4) Click “Register DLL” to run regsvr32 quietly (/s).
   - If you see access denied or elevation required in the log, use “Register (Elevated)”.

## Notes
- The app detects the selected DLL’s bitness by reading the PE headers and chooses the correct regsvr32 path.
- For 32-bit process on 64-bit OS needing 64-bit regsvr32, the app uses %SystemRoot%\Sysnative\regsvr32.exe to bypass WOW64 redirection.
- The log area shows:
  - The exact regsvr32 path used
  - The full command line executed
  - Start/End timestamps
  - Process exit code
  - Hints when elevation may be required

## Limitations
- Currently shows direct imports (not a recursive dependency tree).
- Delay-load imports are not enumerated yet.

## Project Structure
- CMakeLists.txt
- src/
  - main.cpp          (Win32 GUI, file picker, UI, logging, registration)
  - pe_utils.h/.cpp   (PE parsing, bitness detection, dependency resolution, regsvr32 path logic)
