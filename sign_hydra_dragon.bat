@echo off
setlocal enabledelayedexpansion

:: Certificate paths
set PFX_FILE=driver\sanctum.pfx
set PFX_PASSWORD=password

:: Development/Test paths (user's Documents folder)
set HYDRA_DRAGON_PATH=C:\Users\%USERNAME%\Documents\HydraDragonAntivirus\HydraDragonAntivirusLauncher.exe
set OWLYSHIELD_PATH=C:\Users\%USERNAME%\Documents\HydraDragonAntivirus\hydradragon\Owlyshield\Owlyshield Service\owlyshield_ransom.exe
set TENSORFLOW_DLL_PATH=C:\Users\%USERNAME%\Documents\HydraDragonAntivirus\hydradragon\OWlyshield\Owlyshield Service\tensorflowlite_c.dll

:: Check if signtool.exe is available
for /f "delims=" %%A in ('where signtool 2^>nul') do set SIGNTOOL_PATH=%%A
if not defined SIGNTOOL_PATH (
    echo [ERROR] signtool.exe not found. Ensure Windows SDK is installed.
    echo [INFO] You can install it from: https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/
    exit /b 1
)

echo [INFO] Using signtool: %SIGNTOOL_PATH%
echo [INFO] Current user: %USERNAME%
echo.

:: Verify that the PFX file exists
if not exist "%PFX_FILE%" (
    echo [ERROR] Certificate file %PFX_FILE% not found.
    exit /b 1
)

echo [INFO] Using certificate: %PFX_FILE%
echo.

:: Counter for successful signs
set SIGN_SUCCESS=0
set SIGN_FAILED=0

:: ==============================
:: Sign HydraDragonAntivirusLauncher
:: ==============================
if exist "%HYDRA_DRAGON_PATH%" (
    echo [1/3] Signing HydraDragonAntivirusLauncher: %HYDRA_DRAGON_PATH%
    "%SIGNTOOL_PATH%" sign /fd SHA256 /v /f "%PFX_FILE%" /p "%PFX_PASSWORD%" "%HYDRA_DRAGON_PATH%"
    if !ERRORLEVEL! EQU 0 (
        echo [SUCCESS] HydraDragonAntivirusLauncher signed successfully!
        set /a SIGN_SUCCESS+=1
    ) else (
        echo [ERROR] Failed to sign HydraDragonAntivirusLauncher.
        set /a SIGN_FAILED+=1
    )
    echo.
) else (
    echo [WARNING] HydraDragonAntivirusLauncher not found: %HYDRA_DRAGON_PATH%
    echo [INFO] Skipping...
    echo.
)

:: ==============================
:: Sign owlyshield_ransom
:: ==============================
if exist "%OWLYSHIELD_PATH%" (
    echo [2/3] Signing owlyshield_ransom: %OWLYSHIELD_PATH%
    "%SIGNTOOL_PATH%" sign /fd SHA256 /v /f "%PFX_FILE%" /p "%PFX_PASSWORD%" "%OWLYSHIELD_PATH%"
    if !ERRORLEVEL! EQU 0 (
        echo [SUCCESS] owlyshield_ransom signed successfully!
        set /a SIGN_SUCCESS+=1
    ) else (
        echo [ERROR] Failed to sign owlyshield_ransom.
        set /a SIGN_FAILED+=1
    )
    echo.
) else (
    echo [WARNING] owlyshield_ransom not found: %OWLYSHIELD_PATH%
    echo [INFO] Skipping...
    echo.
)

:: ==============================
:: Sign tensorflowlite_c.dll
:: ==============================
if exist "%TENSORFLOW_DLL_PATH%" (
    echo [3/3] Signing tensorflowlite_c.dll: %TENSORFLOW_DLL_PATH%
    "%SIGNTOOL_PATH%" sign /fd SHA256 /v /f "%PFX_FILE%" /p "%PFX_PASSWORD%" "%TENSORFLOW_DLL_PATH%"
    if !ERRORLEVEL! EQU 0 (
        echo [SUCCESS] tensorflowlite_c.dll signed successfully!
        set /a SIGN_SUCCESS+=1
    ) else (
        echo [ERROR] Failed to sign tensorflowlite_c.dll.
        set /a SIGN_FAILED+=1
    )
    echo.
) else (
    echo [WARNING] tensorflowlite_c.dll not found: %TENSORFLOW_DLL_PATH%
    echo [INFO] Skipping...
    echo.
)

:: ==============================
:: Summary
:: ==============================
echo ========================================
echo SIGNING SUMMARY
echo ========================================
echo Successfully signed: !SIGN_SUCCESS!
echo Failed to sign:      !SIGN_FAILED!
echo ========================================

if !SIGN_FAILED! GTR 0 (
    echo [WARNING] Some files failed to sign!
    exit /b 1
)

if !SIGN_SUCCESS! EQU 0 (
    echo [ERROR] No files were signed. Check file paths.
    exit /b 1
)

echo [SUCCESS] All available binaries signed successfully!
endlocal
exit /b 0
