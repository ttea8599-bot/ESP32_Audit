@echo off
setlocal
title ESP32 AUDIT - FLASH

set PORT=%1
if "%PORT%"=="" set PORT=COM3

set FS_OFFSET=0x290000
set BAUD=921600

echo ============================================
echo   ESP32 AUDIT - Flash to %PORT%
echo ============================================
echo.

if not exist ".build\out\ESP32_Audit.ino.bin" (
  echo [!] No build found. Run build.bat first.
  pause & exit /b 1
)

echo [1/3] Building LittleFS image...
python tools\build_fs.py
if errorlevel 1 ( echo [!] fs build failed & pause & exit /b 1 )

echo [2/3] Flashing firmware...
python -m esptool --chip esp32 --port %PORT% --baud %BAUD% ^
  --before default_reset --after hard_reset ^
  write_flash -z --flash_mode dio --flash_freq 40m --flash_size detect ^
  0x1000   .build\out\ESP32_Audit.ino.bootloader.bin ^
  0x8000   .build\out\ESP32_Audit.ino.partitions.bin ^
  0xe000   .build\out\boot_app0.bin ^
  0x10000  .build\out\ESP32_Audit.ino.bin

if errorlevel 1 ( echo [!] Flash failed & pause & exit /b 1 )

echo [3/3] Flashing filesystem...
python -m esptool --chip esp32 --port %PORT% --baud %BAUD% ^
  write_flash %FS_OFFSET% .build\littlefs.bin

echo.
echo [OK] Done. Open http://192.168.4.1/admin.html
pause