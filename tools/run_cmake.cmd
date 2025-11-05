@echo off
setlocal

set "CMAKE=tools\cmake\cmake-4.1.2-windows-x86_64\bin\cmake.exe"
echo [INFO] Expecting CMake at "%CMAKE%"

if not exist "%CMAKE%" (
  echo [ERROR] CMake not found at "%CMAKE%"
  echo [INFO] Listing potential locations under tools\cmake...
  dir /s /b tools\cmake\cmake-*\bin\cmake.exe 2>nul
  exit /b 1
)

echo [INFO] Setting CMAKE_ROOT for portable CMake...
set "CMAKE_ROOT=tools\cmake\cmake-4.1.2-windows-x86_64\share\cmake-4.1"
if not exist "%CMAKE_ROOT%" (
  echo [WARN] Expected CMAKE_ROOT not found at "%CMAKE_ROOT%"
) else (
  echo [INFO] Using CMAKE_ROOT="%CMAKE_ROOT%"
)

echo [INFO] CMake version:
"%CMAKE%" --version
if not "%ERRORLEVEL%"=="0" (
  echo [ERROR] Failed to execute CMake.
  exit /b %ERRORLEVEL%
)

echo [STEP] Configure (VS 2022, x64)...
"%CMAKE%" -S "%CD%" -B "build\vs2022-x64" -G "Visual Studio 17 2022" -A x64
if not "%ERRORLEVEL%"=="0" (
  echo [ERROR] Configure failed with code %ERRORLEVEL%.
  exit /b %ERRORLEVEL%
)

echo [STEP] Build Release...
"%CMAKE%" --build "build\vs2022-x64" --config Release
set "ERR=%ERRORLEVEL%"
if not "%ERR%"=="0" (
  echo [ERROR] Build failed with code %ERR%.
  exit /b %ERR%
)

echo [OK] Build complete. Run:
echo   build\vs2022-x64\bin\Release\DependencyExplorer.exe
exit /b 0
