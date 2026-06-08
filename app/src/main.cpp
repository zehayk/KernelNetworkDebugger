// main.cpp - knetdbg entry point: Win32 + D3D11 + Dear ImGui (docking + multi-
// viewport), driving the KndClient -> KndModel -> UI pipeline each frame.

#include "ui.h"
#include "knd_client.h"
#include "app_model.h"
#include "mock.h"

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#include <d3d11.h>
#include <tchar.h>
#include <cwchar>

// ---- D3D11 plumbing (mirrors the official example_win32_directx11) ----
static ID3D11Device*           g_pd3dDevice = nullptr;
static ID3D11DeviceContext*    g_pd3dDeviceContext = nullptr;
static IDXGISwapChain*         g_pSwapChain = nullptr;
static ID3D11RenderTargetView* g_mainRTV = nullptr;
static UINT                    g_ResizeW = 0, g_ResizeH = 0;

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

static void CreateRenderTarget()
{
    ID3D11Texture2D* back = nullptr;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&back));
    if (back) {
        g_pd3dDevice->CreateRenderTargetView(back, nullptr, &g_mainRTV);
        back->Release();
    }
}

static void CleanupRenderTarget()
{
    if (g_mainRTV) { g_mainRTV->Release(); g_mainRTV = nullptr; }
}

static bool CreateDeviceD3D(HWND hWnd)
{
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT flags = 0;
    D3D_FEATURE_LEVEL fl;
    const D3D_FEATURE_LEVEL levels[] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };

    HRESULT hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, flags,
                                               levels, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain,
                                               &g_pd3dDevice, &fl, &g_pd3dDeviceContext);
    if (FAILED(hr)) {
        // Analysis VMs frequently lack a hardware GPU; fall back to the WARP
        // software rasterizer so the UI still renders.
        hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, flags,
                                           levels, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain,
                                           &g_pd3dDevice, &fl, &g_pd3dDeviceContext);
    }
    if (FAILED(hr)) {
        return false;
    }
    CreateRenderTarget();
    return true;
}

static void CleanupDeviceD3D()
{
    CleanupRenderTarget();
    if (g_pSwapChain)        { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice)        { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) {
        return true;
    }
    switch (msg) {
    case WM_SIZE:
        if (wParam != SIZE_MINIMIZED) {
            g_ResizeW = (UINT)LOWORD(lParam);
            g_ResizeH = (UINT)HIWORD(lParam);
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) { return 0; } // disable ALT app menu
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

int APIENTRY wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR lpCmdLine, int)
{
    const bool demoFromCmd = (lpCmdLine != nullptr && wcsstr(lpCmdLine, L"demo") != nullptr);
    const bool mitmFromCmd = (lpCmdLine != nullptr && wcsstr(lpCmdLine, L"mitm") != nullptr);

    ImGui_ImplWin32_EnableDpiAwareness();

    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0, 0, hInst, nullptr, nullptr,
                       nullptr, nullptr, L"knetdbg", nullptr };
    RegisterClassExW(&wc);
    HWND hwnd = CreateWindowW(wc.lpszClassName, L"knetdbg — kernel network debugger",
                              WS_OVERLAPPEDWINDOW, 100, 100, 1380, 860,
                              nullptr, nullptr, wc.hInstance, nullptr);

    if (!CreateDeviceD3D(hwnd)) {
        CleanupDeviceD3D();
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = "knetdbg_layout.ini";   // persist docking layout across runs

    AppState st;
    st.mockData = demoFromCmd;
    Ui_ApplyTheme(st);

    // Only impose the default dock layout on the first ever run; on later runs
    // the saved ini restores the user's own arrangement (and "Reset layout"
    // forces the default back).
    st.layoutInitialized = (GetFileAttributesA(io.IniFilename) != INVALID_FILE_ATTRIBUTES);

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    KndClient client;
    KndModel  model;
    KndMitmCa mitmCa;
    KndMitmProxy mitmProxy;
    {
        // Generate (first run) or load the local MITM CA. This only creates local
        // files; it installs/intercepts nothing until the user acts in the UI.
        std::string caErr;
        mitmCa.loadOrCreate("knd_ca.pem", "knd_ca_key.pem", &caErr);
    }
    if (mitmFromCmd) {
        std::string e;
        mitmProxy.start(8888, &mitmCa, &e);   // headless self-test entry point
    }

    // Try to attach to the driver at startup; if it isn't loaded the UI shows a
    // Reconnect button rather than failing.
    if (client.open() && client.mapRing()) {
        st.deviceConnected = true;
        st.ringMapped = true;
        std::snprintf(st.status, sizeof(st.status), "Connected — ring mapped");
    } else {
        std::snprintf(st.status, sizeof(st.status),
                      "Driver not found — load knd.sys in the VM, then Reconnect");
    }

    const float clear[4] = { 0.045f, 0.048f, 0.058f, 1.0f };
    bool done = false;
    while (!done) {
        MSG msg;
        while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            if (msg.message == WM_QUIT) { done = true; }
        }
        if (done) { break; }

        if (g_ResizeW != 0 && g_ResizeH != 0) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, g_ResizeW, g_ResizeH, DXGI_FORMAT_UNKNOWN, 0);
            g_ResizeW = g_ResizeH = 0;
            CreateRenderTarget();
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        // Drain the kernel ring into the model (no-op until mapped + capturing).
        const double now = ImGui::GetTime();
        if (st.ringMapped) {
            client.poll([&](const KND_RECORD* rec) { model.ingest(rec, now); });
        }
        if (st.mockData) {
            Mock_Pump(model, now);
        }
        // Drain MITM-proxy plaintext into the model (no-op unless the proxy runs).
        mitmProxy.drain([&](const KND_RECORD* rec) { model.ingest(rec, now); });

        Ui_Frame(model, client, mitmCa, mitmProxy, st);

        if (ImGui::GetMainViewport()->PlatformRequestClose) { done = true; }

        ImGui::Render();
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRTV, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRTV, clear);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable) {
            ImGui::UpdatePlatformWindows();
            ImGui::RenderPlatformWindowsDefault();
        }

        g_pSwapChain->Present(1, 0);   // vsync
    }

    mitmProxy.stop();
    client.close();
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    return 0;
}
