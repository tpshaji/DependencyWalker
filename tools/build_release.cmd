@echo off
setlocal ENABLEDELAYEDEXPANSION

REM Find CMake (installed, portable, or PATH)
set "CMAKE_EXE="
if exist "C:\Program Files\CMake\bin\cmake.exe" (
  set "CMAKE_EXE=C:\Program Files\CMake\bin\cmake.exe"
) else (
  if exist ".\tools\cmake" (
    for /f "delims=" %%i in ('dir /s /b ".\tools\cmake\cmake-*\bin\cmake.exe" 2^>nul') do (
      if not defined CMAKE_EXE set "CMAKE_EXE=%%i"
    )
  )
)

if not defined CMAKE_EXE (
  where cmake >nul 2>nul
  if "!ERRORLEVEL!"=="0" (
    set "CMAKE_EXE=cmake"
  )
)

if not defined CMAKE_EXE (
  echo [ERROR] CMake not found. Install CMake or run portable bootstrap:
  echo   - winget install -e --id Kitware.CMake
  echo   - or use: tools\configure_vs2022_x64.cmd after CMake install completes
  echo   - or download portable CMake into tools\cmake\... as cmake-*\bin\cmake.exe
  exit /b 1
)

echo [INFO] Using CMake: "!CMAKE_EXE!"

REM Configure (Visual Studio 2022 generator, x64)
"!CMAKE_EXE!" -S "%CD%" -B "build\vs2022-x64" -G "Visual Studio 17 2022" -A x64
if not "!ERRORLEVEL!"=="0" (
  echo [ERROR] CMake configure failed. Code=!ERRORLEVEL!
  exit /b !ERRORLEVEL!
)

REM Build Release
"!CMAKE_EXE!" --build "build\vs2022-x64" --config Release
if not "!ERRORLEVEL!"=="0" (
  echo [ERROR] CMake build failed. Code=!ERRORLEVEL!
  exit /b !ERRORLEVEL!
)

echo [OK] Build complete.
echo [RUN] build\vs2022-x64\bin\Release\DependencyExplorer.exe
exit /b 0
