@echo off
setlocal enabledelayedexpansion
title User Sync Utility
color 0A
mode con: cols=100 lines=35

:: --- Set working folder ---
cd "C:\Users\vboxuser\Desktop\New folder"
echo.
echo [NOTE] Replace the directory above with your own path.
echo.

:: --- Check Condition.txt exists ---
if not exist "Condition.txt" (
    color 0C
    echo [ERROR] Missing file: "Condition.txt"
    echo Please make a file named "Condition.txt" with format:
    echo   Name, Access level
    echo Example:
    echo   John, admin
    echo   Alex, user
    pause
    exit /b
)

:: --- Check admin privileges ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    color 0C
    echo [ERROR] Please run this script as Administrator.
    pause
    exit /b
)

cls
echo =====================================
echo =====       Syncing Users       =====
echo =====================================
echo.

:: --- Set protected users ---
set "currentUser=%USERNAME%"
set "protected=Administrator Guest DefaultAccount WDAGUtilityAccount %currentUser%"
echo Current user: %currentUser%
echo Protected users: %protected%
echo.

:: --- Read system users safely using PowerShell ---
echo [INFO] Reading system users...
set "sysUsers="
for /f "tokens=*" %%U in ('powershell -Command "Get-LocalUser | Select-Object -ExpandProperty Name"') do (
    set "sysUsers=!sysUsers! %%U"
)

if "!sysUsers!"=="" (
    color 0C
    echo [ERROR] Failed to read system users via PowerShell.
    pause
    exit /b
)

echo [INFO] Found system users: !sysUsers!
echo.

:: --- Process Condition.txt safely ---
echo [INFO] Processing users from Condition.txt...
for /f "usebackq tokens=1,2 delims=," %%A in ("Condition.txt") do (
    set "name=%%~A"
    set "role=%%~B"

    :: Trim spaces
    for /f "tokens=* delims= " %%Z in ("!name!") do set "name=%%Z"
    for /f "tokens=* delims= " %%Z in ("!role!") do set "role=%%Z"

    :: Skip blank lines
    if "!name!"=="" (
        set "skipLine=1"
    ) else (
        set "skipLine=0"
    )

    if "!skipLine!"=="0" (
        echo.
        echo -------------------------------------
        echo User: !name!
        echo Role: !role!

        :: Skip protected users
        echo !protected! | findstr /i "\<!name!\>" >nul
        if !errorlevel! == 0 (
            echo [SKIP] Protected user - skipping.
        ) else (
            :: Check if user exists
            echo !sysUsers! | findstr /i "\<!name!\>" >nul
            if !errorlevel! == 0 (
                echo [OK] User !name! already exists.
            ) else (
                :: Create user
                echo [CREATE] Creating user "!name!"...
                choice /c YN /m "Do you want to set a password for !name!?"
                if errorlevel 2 (
                    net user "!name!" /add >nul 2>&1
                    echo [DONE] Added user "!name!" with no password.
                ) else (
                    set /p "password=Enter password for !name!: "
                    net user "!name!" "!password!" /add >nul 2>&1
                    echo [DONE] Added user "!name!" with custom password.
                )

                :: Grant admin if needed
                if /I "!role!"=="admin" (
                    net localgroup Administrators "!name!" /add >nul 2>&1
                    echo [GRANTED] Added to Administrators group.
                )
            )
        )
    )
)

echo.
color 0B
echo =====================================
echo Sync Complete - All users processed.
echo =====================================
pause
exit /b
