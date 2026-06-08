@echo off
rem build_all.bat - build + sign every component (driver, mbedTLS, app) into dist\.
rem Run from any shell; it enters the VS x64 toolchain itself.
setlocal
set "ROOT=%~dp0"
echo === knetdbg full build ===

rem --- ensure the x64 MSVC toolchain is active ---
where cl >nul 2>nul && goto have_cl
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto no_cl
"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath > "%TEMP%\_knd_vs.txt"
set /p VSPATH=<"%TEMP%\_knd_vs.txt"
del "%TEMP%\_knd_vs.txt" >nul 2>nul
if defined VSPATH call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul
:have_cl
where cl >nul 2>nul || goto no_cl

rem --- 1. kernel driver: build (VS v17.0 WDK tooling) + sign. Non-fatal if WDK absent ---
echo [1/3] building + signing driver knd.sys ...
set "DRIVER_OK=0"
where msbuild >nul 2>nul && ( call "%ROOT%driver\build_driver.bat" && set "DRIVER_OK=1" )
if "%DRIVER_OK%"=="0" echo   driver not built ^(WDK missing or build error^) - continuing

rem --- 2. usermode app (CMake + Ninja; also builds vendored mbedTLS) ---
echo [2/3] building app knetdbg.exe ...
cmake -G Ninja -S "%ROOT%app" -B "%ROOT%app\build"
if errorlevel 1 (
    echo   stale/invalid build cache - reconfiguring clean ...
    rmdir /s /q "%ROOT%app\build" 2>nul
    cmake -G Ninja -S "%ROOT%app" -B "%ROOT%app\build" || ( echo app configure FAILED & exit /b 1 )
)
cmake --build "%ROOT%app\build" || ( echo app build FAILED & exit /b 1 )

rem --- 3. stage outputs ---
echo [3/3] staging dist\ ...
if not exist "%ROOT%dist" mkdir "%ROOT%dist"
copy /y "%ROOT%app\build\knetdbg.exe" "%ROOT%dist\" >nul
if exist "%ROOT%driver\knd.inf" copy /y "%ROOT%driver\knd.inf" "%ROOT%dist\" >nul
if "%DRIVER_OK%"=="1" copy /y "%ROOT%driver\x64\Release\knd.sys" "%ROOT%dist\" >nul
if exist "%ROOT%certificates\knetdbg_test.cer" copy /y "%ROOT%certificates\knetdbg_test.cer" "%ROOT%dist\" >nul

echo.
echo === done ===
echo   app:    %ROOT%dist\knetdbg.exe
if "%DRIVER_OK%"=="1" ( echo   driver: %ROOT%dist\knd.sys ^(signed^) ) else ( echo   driver: NOT built - see errors above )
echo.
echo To load the driver in the VM ^(only the VM, never the host^):
echo   certutil -addstore Root certificates\knetdbg_test.cer
echo   certutil -addstore TrustedPublisher certificates\knetdbg_test.cer
echo   bcdedit /set testsigning on   ^(reboot^), then use the app's "Load driver" button.
goto :eof

:no_cl
echo ERROR: MSVC (cl.exe) not found. Open a "x64 Native Tools Command Prompt" or install VS C++ tools.
exit /b 1
