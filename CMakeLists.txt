cmake_minimum_required(VERSION 3.16)

project(esp32_audit C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

set(FW_NAME    "ESP32_Audit")
set(FW_VERSION "2.1.0")

# ---------- sources ----------
set(APP_SOURCES
    ESP32_Audit.ino
    terminal.cpp
    storage.cpp
    wifi_engine.cpp
    attacks.cpp
    ble_engine.cpp
    net_tools.cpp
    webui.cpp
)

idf_component_register(
    SRCS            ${APP_SOURCES}
    INCLUDE_DIRS    "."
    REQUIRES        arduino
                    esp_wifi
                    esp_netif
                    nvs_flash
                    driver
                    esp_event
                    freertos
                    bt
    EMBED_FILES     "data/admin.html"
                    "data/login.html"
                    "data/portal.html"
                    "data/style.css"
                    "data/app.js"
)

target_compile_definitions(${COMPONENT_LIB} PRIVATE
    FW_NAME="${FW_NAME}"
    FW_VERSION="${FW_VERSION}"
    CORE_DEBUG_LEVEL=2
)

# ---------- littlefs image ----------
set(FS_DIR   "${CMAKE_CURRENT_SOURCE_DIR}/data")
set(FS_IMAGE "${CMAKE_BINARY_DIR}/littlefs.bin")
set(MKLITTLEFS "${CMAKE_BINARY_DIR}/mklittlefs")

add_custom_target(fs
    COMMAND ${MKLITTLEFS} -c ${FS_IMAGE} -b 4096 -p 256 -s 0x160000 ${FS_DIR}
    COMMENT "Building LittleFS image"
)

add_custom_target(flashfs
    DEPENDS fs
    COMMAND python -m esptool --chip esp32 --port ${PORT} write_flash 0x290000 ${FS_IMAGE}
    COMMENT "Flashing LittleFS image"
)