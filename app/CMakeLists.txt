cmake_minimum_required(VERSION 3.20)
project(knetdbg LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(IMGUI_DIR  ${CMAKE_CURRENT_SOURCE_DIR}/../external/imgui)
set(COMMON_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../common)

add_executable(knetdbg WIN32
    src/main.cpp
    src/knd_client.cpp
    src/app_model.cpp
    src/ui.cpp
    src/mock.cpp
    src/http_parse.cpp
    src/mitm_ca.cpp
    src/mitm_proxy.cpp
    src/knd_service.cpp
    src/win_integration.cpp
    # vendored Dear ImGui (docking branch) + Win32/DX11 backends
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/imgui_demo.cpp
    ${IMGUI_DIR}/imgui_impl_win32.cpp
    ${IMGUI_DIR}/imgui_impl_dx11.cpp
)

target_include_directories(knetdbg PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${IMGUI_DIR}
    ${COMMON_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../external/mbedtls/include
)

target_compile_definitions(knetdbg PRIVATE
    UNICODE _UNICODE
    WIN32_LEAN_AND_MEAN NOMINMAX
    IMGUI_DEFINE_MATH_OPERATORS
)

target_link_libraries(knetdbg PRIVATE
    d3d11 dxgi d3dcompiler dwmapi
    mbedtls mbedx509 mbedcrypto      # MITM TLS
    crypt32 ws2_32 wininet advapi32  # CA install, sockets, system proxy, SCM
)

if (MSVC)
    target_compile_options(knetdbg PRIVATE /W3 /MP /permissive-)
endif()

# --- mbedTLS (vendored, for MITM mode) ---
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING  OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../external/mbedtls
                 ${CMAKE_BINARY_DIR}/mbedtls EXCLUDE_FROM_ALL)

# Step-0 spike target (not part of the default build).
add_executable(tls_spike src/tls_spike.cpp)
target_link_libraries(tls_spike PRIVATE mbedtls mbedx509 mbedcrypto)
