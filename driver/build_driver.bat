@echo off
rem build_driver.bat - build knd.sys with the WDK toolchain. Run from any shell.
setlocal
where cl >nul 2>nul && goto have
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" ( echo vswhere not found & exit /b 1 )
"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath > "%TEMP%\_knd_vs.txt"
set /p VSPATH=<"%TEMP%\_knd_vs.txt"
del "%TEMP%\_knd_vs.txt" >nul 2>nul
if defined VSPATH call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul
:have
rem The installed WDK integrates with VS v17.0 (Microsoft.DriverKit.Build.Tasks.17.0.dll),
rem so pin the driver build to that even on a newer VS.
msbuild "%~dp0knd.vcxproj" /p:Configuration=Release /p:Platform=x64 /p:VisualStudioVersion=17.0 /v:m /nologo || exit /b 1

echo --- signing knd.sys ---
set "SYS=%~dp0x64\Release\knd.sys"
set "PROVIDED=%~dp0..\certificates\SHISHI_HangHao_Abc123456.pfx"
set "TESTPFX=%~dp0..\certificates\knetdbg_test.pfx"

rem Try the provided cert first (as requested); it is expired (2014) so this will
rem normally fail, and we fall back to a freshly generated, valid test cert.
signtool sign /f "%PROVIDED%" /p Abc123456 /fd sha256 "%SYS%" 2>nul
if not errorlevel 1 ( echo signed with provided cert & goto signed )

echo provided cert unusable ^(expired/invalid^) - using a self-signed test cert
if not exist "%TESTPFX%" powershell -ExecutionPolicy Bypass -File "%~dp0make_test_cert.ps1"
signtool sign /f "%TESTPFX%" /p knetdbg /fd sha256 "%SYS%" || ( echo signing FAILED & exit /b 1 )
echo signed with self-signed test cert ^(trust certificates\knetdbg_test.cer + testsigning on in the VM^)
:signed
