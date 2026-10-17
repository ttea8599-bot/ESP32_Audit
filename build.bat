@echo off
setlocal
title ESP32 AUDIT - BUILD

set FW=ESP32_Audit
set CORE=esp32:esp32:esp32

echo ============================================
echo   ESP32 AUDIT - Firmware Build
echo ============================================
echo.

where arduino-cli >nul 2>&1
if errorlevel 1 (
  echo [!] arduino-cli not found in PATH.
  echo     Install: https://arduino.github.io/arduino-cli/
  pause & exit /b 1
)

echo [1/4] Installing core...
arduino-cli core install %CORE% >nul 2>&1

echo [2/4] Installing libraries...
for %%L in (ESPAsyncWebServer AsyncTCP ArduinoJson) do (
  arduino-cli lib install %%L >nul 2>&1
)

echo [3/4] Building LittleFS image...
python tools\build_fs.py

echo [4/4] Compiling %FW%...
arduino-cli compile ^
  --fqbn %CORE%:PartitionScheme=min_spiffs ^
  --build-path .build ^
  --output-dir .build\out ^
  .

if errorlevel 1 (
  echo.
  echo [!] BUILD FAILED
  pause & exit /b 1
)

echo.
echo [OK] Build complete. Binary in .build\out\
echo      Run flash.bat to upload.
pause