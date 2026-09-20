@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul

:: ==============================================================================
:: SELF-ELEVATE TO ADMIN
:: ==============================================================================
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrative privileges...
    set "ELEV_ARGS="
    for %%A in (%*) do set "ELEV_ARGS=!ELEV_ARGS! ""%%~A"""
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs -ArgumentList '!ELEV_ARGS!' -WorkingDirectory '%~dp0'"
    exit /b
)

:: ==============================================================================
:: CROSS-SUITE AUTONOMOUS BOOTSTRAPPER
:: ==============================================================================

cd /d "%~dp0"

:: Set proxy for dependency downloads
set "GOPROXY=https://proxy.golang.org,direct"
set "GOSUMDB=sum.golang.org"

echo ==============================================================================
echo  ==^>^> CROSS-SUITE AUTONOMOUS BOOTSTRAPPER
echo ==============================================================================

:: ----------------------------------------------------------------------------
:: 1. KILL RUNNING INSTANCE
:: ----------------------------------------------------------------------------
tasklist /FI "IMAGENAME eq Cross-Suite_Wizard.exe" 2>NUL | find /I "Cross-Suite_Wizard.exe" >NUL
if %errorlevel% equ 0 (
    echo [+] Cross-Suite_Wizard.exe is running - killing it...
    taskkill /F /IM Cross-Suite_Wizard.exe >nul 2>&1
    timeout /t 2 /nobreak >nul
)

:: ----------------------------------------------------------------------------
:: 2. DETECT GO COMPILER (do NOT override GOROOT - let Go manage its own
::    toolchain switching, since go.mod may require a newer version than
::    the locally installed compiler, which Go downloads automatically)
:: ----------------------------------------------------------------------------
set "GO_FOUND=0"

where go >nul 2>nul
if %errorlevel% equ 0 (
    set "GO_FOUND=1"
    for /f "delims=" %%i in ('where go') do echo [+] Go found at: %%i
)

if %GO_FOUND% equ 0 (
    if exist "C:\Go\bin\go.exe" (
        set "GO_FOUND=1"
        set "PATH=%PATH%;C:\Go\bin"
        echo [+] Go found in C:\Go
    )
)
if %GO_FOUND% equ 0 (
    if exist "C:\Program Files\Go\bin\go.exe" (
        set "GO_FOUND=1"
        set "PATH=%PATH%;C:\Program Files\Go\bin"
        echo [+] Go found in Program Files
    )
)

if defined GOROOT (
    if not exist "%GOROOT%\src\runtime" (
        echo [!] WARNING: GOROOT is set to "%GOROOT%" but no valid Go stdlib
        echo     was found there. Clearing it for this session.
        set "GOROOT="
    )
)

if %GO_FOUND% equ 1 goto :PARSE_FLAGS

:: ----------------------------------------------------------------------------
:: 3. DOWNLOAD AND INSTALL GO (if missing)
:: ----------------------------------------------------------------------------
set "GO_ARCH=amd64"
if "%PROCESSOR_ARCHITECTURE%"=="AMD64" set "GO_ARCH=amd64"
if "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "GO_ARCH=arm64"
if "%PROCESSOR_ARCHITECTURE%"=="x86" set "GO_ARCH=386"

set "GO_VERSION=1.22.5"
set "GO_INSTALLER=go%GO_VERSION%.windows-%GO_ARCH%.msi"
set "GO_URL=https://go.dev/dl/%GO_INSTALLER%"
set "TEMP_INSTALLER=%TEMP%\%GO_INSTALLER%"

echo [!] Go not found. Installing...
echo [+] Downloading from: %GO_URL%

where curl >nul 2>nul
if %errorlevel% neq 0 (
    echo [+] Downloading portable curl...
    powershell -NoProfile -Command "$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -Uri 'https://curl.se/windows/latest/curl-x64.zip' -OutFile '%TEMP%\curl.zip'"
    if exist "%TEMP%\curl.zip" (
        powershell -NoProfile -Command "Expand-Archive -Path '%TEMP%\curl.zip' -DestinationPath '%TEMP%\curl_temp' -Force"
        copy /y "%TEMP%\curl_temp\*\curl.exe" "%TEMP%\curl.exe" >nul
        rmdir /s /q "%TEMP%\curl_temp" 2>nul
        del "%TEMP%\curl.zip"
    )
)

if exist "%TEMP%\curl.exe" (
    echo [+] Using curl to download Go MSI...
    "%TEMP%\curl.exe" -L -o "%TEMP_INSTALLER%" "%GO_URL%"
) else (
    echo [+] Using PowerShell to download...
    powershell -NoProfile -Command "$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -Uri '%GO_URL%' -OutFile '%TEMP_INSTALLER%'"
)

if not exist "%TEMP_INSTALLER%" (
    echo [!] Download failed.
    pause
    exit /b 1
)

echo [+] Installing Go (passive)...
start /wait msiexec /i "%TEMP_INSTALLER%" /passive /norestart

del "%TEMP%\curl.exe" 2>nul
del "%TEMP%\curl.zip" 2>nul

where go >nul 2>nul
if %errorlevel% equ 0 set "GO_FOUND=1"
if exist "C:\Go\bin\go.exe" (
    set "GO_FOUND=1"
    set "PATH=%PATH%;C:\Go\bin"
)
if exist "C:\Program Files\Go\bin\go.exe" (
    set "GO_FOUND=1"
    set "PATH=%PATH%;C:\Program Files\Go\bin"
)

if %GO_FOUND% equ 0 (
    echo [!] Installation failed. Please run the MSI manually:
    echo     %TEMP_INSTALLER%
    pause
    exit /b 1
)

echo [+] Go installed successfully.

:: ----------------------------------------------------------------------------
:: 4. PARSE FLAGS
:: ----------------------------------------------------------------------------
:PARSE_FLAGS
set "BUILD_ALL=0"
set "FORCE_BUILD=0"

if "%~1"=="--all" set "BUILD_ALL=1"
if "%~1"=="-a" set "BUILD_ALL=1"
if "%~1"=="all" set "BUILD_ALL=1"
if "%~1"=="cross" set "BUILD_ALL=1"
if "%~1"=="-f" set "FORCE_BUILD=1"
if "%~1"=="--force" set "FORCE_BUILD=1"
if "%~1"=="-b" set "FORCE_BUILD=1"
if "%~1"=="--build" set "FORCE_BUILD=1"
if "%~1"=="--hard" set "FORCE_BUILD=1"

set "TARGET_BIN=Cross-Suite_Wizard.exe"

:: ----------------------------------------------------------------------------
:: 4b. HARD RESET (--hard only). This calls a subroutine instead of using an
::     inline multi-line if-block, because deeply nested if/for blocks inside
::     a parenthesized if-block are unreliable in cmd.exe. A subroutine runs
::     as plain top-level lines, sidestepping that entirely.
:: ----------------------------------------------------------------------------
if "%~1"=="--hard" call :HARD_RESET

:: ----------------------------------------------------------------------------
:: 5. CROSS-COMPILE
:: ----------------------------------------------------------------------------
if %BUILD_ALL% equ 1 (
    echo ==^>^> Universal cross-compilation...
    if not exist "dist" mkdir "dist"
    set "CGO_ENABLED=0"

    set "GOOS=linux"
    set "GOARCH=amd64"
    go build -ldflags="-s -w" -o dist\Cross-Suite_Wizard-linux-amd64 .

    set "GOOS=linux"
    set "GOARCH=arm64"
    go build -ldflags="-s -w" -o dist\Cross-Suite_Wizard-linux-arm64 .

    set "GOOS=darwin"
    set "GOARCH=amd64"
    go build -ldflags="-s -w" -o dist\Cross-Suite_Wizard-darwin-amd64 .

    set "GOOS=darwin"
    set "GOARCH=arm64"
    go build -ldflags="-s -w" -o dist\Cross-Suite_Wizard-darwin-arm64 .

    set "GOOS=windows"
    set "GOARCH=amd64"
    go build -ldflags="-s -w" -o dist\Cross-Suite_Wizard-windows-amd64.exe .
    go build -ldflags="-s -w" -o "%TARGET_BIN%" .

    echo ==^>^> Builds in .\dist\
    exit /b 0
)

:: ----------------------------------------------------------------------------
:: 6. LOCAL REBUILD
:: ----------------------------------------------------------------------------
set "NEEDS_REBUILD=0"
if not exist "%TARGET_BIN%" set "NEEDS_REBUILD=1"
if %FORCE_BUILD% equ 1 set "NEEDS_REBUILD=1"

if %NEEDS_REBUILD% equ 1 (
    echo [+] Rebuilding %TARGET_BIN%...

    if exist "%TARGET_BIN%" (
        echo [+] Removing old binary...
        del /f /q "%TARGET_BIN%" 2>nul
        if exist "%TARGET_BIN%" (
            echo [+] Could not delete - renaming to .bak...
            move "%TARGET_BIN%" "%TARGET_BIN%.bak" 2>nul
        )
    )

    echo [+] Fetching dependencies - go mod tidy...
    go mod tidy
    if errorlevel 1 (
        echo [!] go mod tidy failed - dependency download may still be
        echo     incomplete. Retrying once...
        go mod tidy
    )

    set "CGO_ENABLED=0"
    set "GOOS=windows"
    set "GOARCH=amd64"

    echo [+] Compiling fresh %TARGET_BIN% ...
    go build -a -ldflags="-s -w" -o "%TARGET_BIN%" .

    if errorlevel 1 (
        echo [!] Build failed.
        if exist "%TARGET_BIN%" ( echo [+] Using existing binary. ) else ( pause & exit /b 1 )
    ) else (
        echo [+] Build successful.
        if exist "%TARGET_BIN%.bak" del /f /q "%TARGET_BIN%.bak" 2>nul
    )
) else (
    echo [+] Binary is up-to-date.
)

:: ----------------------------------------------------------------------------
:: 7. LAUNCH
:: ----------------------------------------------------------------------------
echo ==^>^> Launching Cross-Suite Platform...
"%TARGET_BIN%" %*
endlocal
exit /b 0

:: ==============================================================================
:: SUBROUTINES
:: ==============================================================================

:HARD_RESET
echo [+] --hard: performing full environment reset...

echo [+] Excluding Go module cache from Windows Defender real-time scanning...
del "%TEMP%\cs_add_exclusion.ps1" >nul 2>&1
echo try { > "%TEMP%\cs_add_exclusion.ps1"
echo     Add-MpPreference -ExclusionPath '%USERPROFILE%\go\pkg\mod' -ErrorAction Stop >> "%TEMP%\cs_add_exclusion.ps1"
echo     Write-Host '[+] Defender exclusion added.' >> "%TEMP%\cs_add_exclusion.ps1"
echo } catch { >> "%TEMP%\cs_add_exclusion.ps1"
echo     Write-Host '[!] Could not add Defender exclusion - Defender may be managed or disabled - continuing.' >> "%TEMP%\cs_add_exclusion.ps1"
echo } >> "%TEMP%\cs_add_exclusion.ps1"
powershell -NoProfile -ExecutionPolicy Bypass -File "%TEMP%\cs_add_exclusion.ps1"
del "%TEMP%\cs_add_exclusion.ps1" >nul 2>&1

echo [+] Removing any stale toolchain download in the module cache...
if exist "%USERPROFILE%\go\pkg\mod\golang.org" (
    for /d %%D in ("%USERPROFILE%\go\pkg\mod\golang.org\toolchain@*") do (
        echo     - clearing %%~nxD
        attrib -r "%%D\*.*" /s /d >nul 2>&1
        rmdir /s /q "%%D" >nul 2>&1
    )
)
if exist "%USERPROFILE%\go\pkg\mod\cache\download\golang.org\toolchain" (
    attrib -r "%USERPROFILE%\go\pkg\mod\cache\download\golang.org\toolchain\*.*" /s /d >nul 2>&1
    rmdir /s /q "%USERPROFILE%\go\pkg\mod\cache\download\golang.org\toolchain" >nul 2>&1
)

echo [+] Clearing full Go build and module cache...
go clean -cache >nul 2>&1
go clean -modcache >nul 2>&1

echo [+] Environment reset complete - proceeding to a clean rebuild.
exit /b