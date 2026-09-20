@echo off
:: ==============================================================================
:: CROSS-SUITE FORCE REBUILD & CACHE PURGE (HARD MODE)
:: Comprehensive Deep-Clean, Module Cache Invalidation & Fresh Compilation
:: ==============================================================================
setlocal enabledelayedexpansion

cd /d "%~dp0"

echo ==============================================================================
echo  ==>> INITIALIZING HARD REBUILD ^& ZERO-CACHE ENGINE
echo ==============================================================================
echo [+] Target Directory: %CD%
echo [+] Purging build caches and forcing module re-download...

:: 1. DELEGATE DIRECTLY TO MAIN BOOTSTRAPPER IN FORCE MODE
call "%~dp0autorun.bat" --hard %*

:: 2. CAPTURE EXIT STATUS
set "EXIT_CODE=%errorlevel%"

if %EXIT_CODE% neq 0 (
    echo.
    echo ==============================================================================
    echo  [!] HARD REBUILD FAILED WITH EXIT CODE: %EXIT_CODE%
    echo ==============================================================================
    echo [+] Review compiler error traces printed above.
    pause
    exit /b %EXIT_CODE%
)

endlocal