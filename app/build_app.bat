@echo off
rem Build knetdbg.exe: ensure the x64 MSVC toolchain is active, then configure +
rem build with Ninja. Safe to run from either a plain shell or a Developer prompt.
setlocal

rem If cl is already on PATH (e.g. a Developer Command Prompt), skip vcvars.
where cl >nul 2>nul
if %errorlevel%==0 goto :configured

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo Could not find vswhere. Run this from a "x64 Native Tools Command Prompt".
    exit /b 1
)
"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath > "%TEMP%\_knd_vspath.txt"
set /p VSPATH=<"%TEMP%\_knd_vspath.txt"
del "%TEMP%\_knd_vspath.txt" >nul 2>nul
if "%VSPATH%"=="" ( echo Visual Studio with the C++ x64 tools was not found. & exit /b 1 )
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 ( echo vcvars64 failed & exit /b 1 )

:configured
cmake -G Ninja -S "%~dp0." -B "%~dp0build" || exit /b 1
cmake --build "%~dp0build" || exit /b 1
echo.
echo Built: %~dp0build\knetdbg.exe
