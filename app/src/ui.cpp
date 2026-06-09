// ui.cpp - see ui.h. Theme + dockspace + panels + content-driven animations.
#include "ui.h"
#include "http_parse.h"
#include "knd_service.h"
#include "win_integration.h"
#include "knd_inject.h"

#include "imgui.h"
#include "imgui_internal.h"   // DockBuilder*

#include <string>

#include <cstdio>
#include <cstring>
#include <cmath>
#include <algorithm>

// ---------------------------------------------------------------- theme

void Ui_ApplyTheme(const AppState& st)
{
    ImGuiStyle& s = ImGui::GetStyle();
    s.WindowRounding    = 6.0f;
    s.ChildRounding     = 6.0f;
    s.FrameRounding     = 5.0f;
    s.PopupRounding     = 5.0f;
    s.TabRounding       = 5.0f;
    s.GrabRounding      = 4.0f;
    s.ScrollbarRounding = 9.0f;
    s.WindowPadding     = ImVec2(12, 10);
    s.FramePadding      = ImVec2(9, 5);
    s.ItemSpacing       = ImVec2(9, 7);
    s.CellPadding       = ImVec2(8, 4);
    s.WindowBorderSize  = 1.0f;
    s.FrameBorderSize   = 0.0f;
    s.ScrollbarSize     = 12.0f;
    s.GrabMinSize       = 10.0f;

    const ImVec4 acc(st.accent[0], st.accent[1], st.accent[2], 1.0f);
    const ImVec4 accHi(acc.x * 1.15f, acc.y * 1.15f, acc.z * 1.15f, 1.0f);
    auto a = [](ImVec4 c, float al) { c.w = al; return c; };

    ImVec4* col = s.Colors;
    col[ImGuiCol_Text]              = ImVec4(0.90f, 0.91f, 0.93f, 1.00f);
    col[ImGuiCol_TextDisabled]      = ImVec4(0.45f, 0.47f, 0.52f, 1.00f);
    col[ImGuiCol_WindowBg]          = ImVec4(0.069f, 0.074f, 0.090f, 1.00f);
    col[ImGuiCol_ChildBg]           = ImVec4(0.085f, 0.090f, 0.108f, 1.00f);
    col[ImGuiCol_PopupBg]           = ImVec4(0.060f, 0.064f, 0.078f, 0.98f);
    col[ImGuiCol_Border]            = ImVec4(0.16f, 0.17f, 0.20f, 1.00f);
    col[ImGuiCol_FrameBg]           = ImVec4(0.135f, 0.142f, 0.165f, 1.00f);
    col[ImGuiCol_FrameBgHovered]    = ImVec4(0.18f, 0.19f, 0.22f, 1.00f);
    col[ImGuiCol_FrameBgActive]     = a(acc, 0.45f);
    col[ImGuiCol_TitleBg]           = ImVec4(0.055f, 0.059f, 0.072f, 1.00f);
    col[ImGuiCol_TitleBgActive]     = ImVec4(0.075f, 0.080f, 0.098f, 1.00f);
    col[ImGuiCol_MenuBarBg]         = ImVec4(0.085f, 0.090f, 0.108f, 1.00f);
    col[ImGuiCol_Header]            = a(acc, 0.30f);
    col[ImGuiCol_HeaderHovered]     = a(acc, 0.45f);
    col[ImGuiCol_HeaderActive]      = a(acc, 0.60f);
    col[ImGuiCol_Button]            = a(acc, 0.32f);
    col[ImGuiCol_ButtonHovered]     = a(acc, 0.55f);
    col[ImGuiCol_ButtonActive]      = a(accHi, 0.80f);
    col[ImGuiCol_CheckMark]         = accHi;
    col[ImGuiCol_SliderGrab]        = acc;
    col[ImGuiCol_SliderGrabActive]  = accHi;
    col[ImGuiCol_Separator]         = ImVec4(0.16f, 0.17f, 0.20f, 1.00f);
    col[ImGuiCol_Tab]               = ImVec4(0.105f, 0.110f, 0.130f, 1.00f);
    col[ImGuiCol_TabHovered]        = a(acc, 0.55f);
    col[ImGuiCol_TabActive]         = a(acc, 0.40f);
    col[ImGuiCol_TabUnfocused]      = ImVec4(0.09f, 0.095f, 0.115f, 1.00f);
    col[ImGuiCol_TabUnfocusedActive]= ImVec4(0.12f, 0.125f, 0.150f, 1.00f);
    col[ImGuiCol_TableHeaderBg]     = ImVec4(0.115f, 0.120f, 0.142f, 1.00f);
    col[ImGuiCol_TableBorderStrong] = ImVec4(0.16f, 0.17f, 0.20f, 1.00f);
    col[ImGuiCol_TableBorderLight]  = ImVec4(0.13f, 0.14f, 0.16f, 1.00f);
    col[ImGuiCol_TableRowBg]        = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    col[ImGuiCol_TableRowBgAlt]     = ImVec4(1.00f, 1.00f, 1.00f, 0.018f);
    col[ImGuiCol_DockingPreview]    = a(acc, 0.55f);
    col[ImGuiCol_NavHighlight]      = acc;

    // Multi-viewport requires opaque window backgrounds.
    col[ImGuiCol_WindowBg].w = 1.0f;
}

// ---------------------------------------------------------------- helpers

static ImU32 FadeAccent(const AppState& st, float fade01)
{
    return IM_COL32((int)(st.accent[0] * 255), (int)(st.accent[1] * 255),
                    (int)(st.accent[2] * 255), (int)(fade01 * 90));
}

static void Connect(KndClient& client, AppState& st)
{
    if (!client.open()) {
        st.deviceConnected = false;
        st.ringMapped = false;
        std::snprintf(st.status, sizeof(st.status),
                      "Cannot open %ws — is knd.sys loaded? (sc start knd)", KND_DOS_NAME);
        return;
    }
    st.deviceConnected = true;

    KND_VERSION_OUT v{};
    client.getVersion(v);

    st.ringMapped = client.mapRing();
    if (st.ringMapped) {
        std::snprintf(st.status, sizeof(st.status),
                      "Connected — driver v%u, protocol v%u, ring mapped",
                      v.driverVersion, v.protocolVersion);
    } else {
        std::snprintf(st.status, sizeof(st.status),
                      "Connected (driver v%u) but ring map failed", v.driverVersion);
    }
}

// ---------------------------------------------------------------- layout

static void BuildDefaultLayout(ImGuiID dockId)
{
    ImGui::DockBuilderRemoveNode(dockId);
    ImGui::DockBuilderAddNode(dockId, ImGuiDockNodeFlags_DockSpace);
    ImGui::DockBuilderSetNodeSize(dockId, ImGui::GetMainViewport()->Size);

    ImGuiID top, rest, left, right, rtop, rbot;
    ImGui::DockBuilderSplitNode(dockId, ImGuiDir_Up,   0.11f, &top,  &rest);
    ImGui::DockBuilderSplitNode(rest,   ImGuiDir_Left, 0.62f, &left, &right);
    ImGui::DockBuilderSplitNode(right,  ImGuiDir_Up,   0.58f, &rtop, &rbot);

    ImGui::DockBuilderDockWindow("Control",    top);
    ImGui::DockBuilderDockWindow("Flows",      left);
    ImGui::DockBuilderDockWindow("Packets",    left);
    ImGui::DockBuilderDockWindow("Inspector",  rtop);
    ImGui::DockBuilderDockWindow("Statistics", rbot);
    ImGui::DockBuilderDockWindow("MITM",       rbot);
    ImGui::DockBuilderDockWindow("SChannel keys", rbot);
    ImGui::DockBuilderDockWindow("Settings",   rbot);
    ImGui::DockBuilderFinish(dockId);
}

static void DrawMenuBar(AppState& st, KndClient& client, KndModel& model)
{
    if (!ImGui::BeginMainMenuBar()) {
        return;
    }
    if (ImGui::BeginMenu("File")) {
        if (ImGui::MenuItem("Clear capture")) { model.clear(); }
        ImGui::Separator();
        if (ImGui::MenuItem("Exit")) {
            // request close of the main window
            ImGui::GetMainViewport()->PlatformRequestClose = true;
        }
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Capture")) {
        const bool conn = st.deviceConnected;
        if (ImGui::MenuItem("Connect / Reconnect")) { Connect(client, st); }
        if (ImGui::MenuItem("Start", nullptr, false, conn && !st.capturing)) {
            if (client.startCapture()) { st.capturing = true; }
        }
        if (ImGui::MenuItem("Stop", nullptr, false, conn && st.capturing)) {
            if (client.stopCapture()) { st.capturing = false; }
        }
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("View")) {
        if (ImGui::MenuItem("Reset layout")) { st.askResetLayout = true; }
        ImGui::EndMenu();
    }
    ImGui::EndMainMenuBar();
}

// ---------------------------------------------------------------- panels

static std::wstring WidenAscii(const char* s)
{
    std::wstring w;
    for (const char* p = s; *p; ++p) { w.push_back((wchar_t)(unsigned char)*p); }
    return w;
}

static void DrawControl(AppState& st, KndClient& client, KndModel& model)
{
    if (!ImGui::Begin("Control")) { ImGui::End(); return; }

    // --- driver service controls (load/unload via the Service Control Manager) ---
    if (ImGui::Button("Load driver")) {
        std::string e;
        if (KndService::LoadDriver(KND_SERVICE_NAME_W, WidenAscii(st.sysPath), e)) {
            snprintf(st.driverStatus, sizeof(st.driverStatus), "driver: loaded / running");
        } else {
            snprintf(st.driverStatus, sizeof(st.driverStatus), "load failed: %s", e.c_str());
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Unload driver")) {
        std::string e;
        if (KndService::UnloadDriver(KND_SERVICE_NAME_W, e)) {
            snprintf(st.driverStatus, sizeof(st.driverStatus), "driver: unloaded");
        } else {
            snprintf(st.driverStatus, sizeof(st.driverStatus), "unload failed: %s", e.c_str());
        }
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(240);
    ImGui::InputText("##syspath", st.sysPath, sizeof(st.sysPath));
    ImGui::SameLine();
    ImGui::TextDisabled("%s", st.driverStatus);
    ImGui::Separator();

    if (!st.deviceConnected) {
        if (ImGui::Button("Connect", ImVec2(120, 0))) { Connect(client, st); }
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.95f, 0.55f, 0.30f, 1.0f), "%s", st.status);
        ImGui::End();
        return;
    }

    // Big capture toggle.
    if (st.capturing) {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.70f, 0.22f, 0.24f, 0.55f));
        if (ImGui::Button("Stop Capture", ImVec2(150, 0))) {
            if (client.stopCapture()) { st.capturing = false; }
        }
        ImGui::PopStyleColor();
    } else {
        if (ImGui::Button("Start Capture", ImVec2(150, 0))) {
            if (client.startCapture()) { st.capturing = true; }
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Clear", ImVec2(80, 0))) { model.clear(); }

    // LIVE pulse indicator.
    ImGui::SameLine(0, 24);
    if (st.capturing) {
        float pulse = st.animations ? (0.5f + 0.5f * sinf((float)ImGui::GetTime() * 3.2f)) : 1.0f;
        ImGui::TextColored(ImVec4(0.30f, 0.85f, 0.45f, 0.35f + 0.65f * pulse), "%s", "● LIVE");
    } else {
        ImGui::TextColored(ImVec4(0.55f, 0.57f, 0.62f, 1.0f), "%s", "■ idle");
    }

    // Quick counters.
    ImGui::SameLine(0, 28);
    const KndModelStats& ms = model.stats();
    ImGui::Text("flows %zu   records %llu   payload %s",
                model.flows().size(),
                (unsigned long long)ms.totalRecords,
                KndFormatBytes(ms.payloadBytes).c_str());

    ImGui::SameLine();
    ImGui::TextDisabled("|  %s", st.status);
    ImGui::End();
}

static bool FlowMatchesFilter(const KndFlow& f, const AppState& st)
{
    if (!st.showClosed && f.closed) { return false; }
    if (st.filterText[0] == '\0') { return true; }

    char hay[512];
    std::snprintf(hay, sizeof(hay), "%s %s %u %s %u %s",
                  f.processName.c_str(),
                  KndFormatAddr(f.remoteAddr, f.ipVersion).c_str(), f.remotePort,
                  KndFormatAddr(f.localAddr, f.ipVersion).c_str(), f.localPort,
                  KndFormatProto(f.protocol).c_str());
    // case-insensitive substring
    std::string h(hay), n(st.filterText);
    std::transform(h.begin(), h.end(), h.begin(), ::tolower);
    std::transform(n.begin(), n.end(), n.begin(), ::tolower);
    return h.find(n) != std::string::npos;
}

static void DrawFlows(KndModel& model, AppState& st)
{
    if (!ImGui::Begin("Flows")) { ImGui::End(); return; }

    ImGui::SetNextItemWidth(260);
    ImGui::InputTextWithHint("##filter", "filter: process / ip / port…",
                             st.filterText, sizeof(st.filterText));
    ImGui::SameLine();
    ImGui::Checkbox("show closed", &st.showClosed);
    ImGui::SameLine();
    ImGui::TextDisabled("(%zu connections)", model.flows().size());

    const ImGuiTableFlags tf = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH |
                               ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable |
                               ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable |
                               ImGuiTableFlags_SizingStretchProp;

    if (ImGui::BeginTable("flows", 9, tf)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Time",    ImGuiTableColumnFlags_WidthFixed, 90);
        ImGui::TableSetupColumn("Process", ImGuiTableColumnFlags_WidthStretch, 1.4f);
        ImGui::TableSetupColumn("PID",     ImGuiTableColumnFlags_WidthFixed, 56);
        ImGui::TableSetupColumn("Proto",   ImGuiTableColumnFlags_WidthFixed, 52);
        ImGui::TableSetupColumn("Remote",  ImGuiTableColumnFlags_WidthStretch, 1.6f);
        ImGui::TableSetupColumn("Dir",     ImGuiTableColumnFlags_WidthFixed, 44);
        ImGui::TableSetupColumn("Out",     ImGuiTableColumnFlags_WidthFixed, 76);
        ImGui::TableSetupColumn("In",      ImGuiTableColumnFlags_WidthFixed, 76);
        ImGui::TableSetupColumn("State",   ImGuiTableColumnFlags_WidthFixed, 60);
        ImGui::TableHeadersRow();

        const double now = ImGui::GetTime();
        const auto& flows = model.flows();
        for (size_t i = 0; i < flows.size(); ++i) {
            const KndFlow& f = flows[i];
            if (!FlowMatchesFilter(f, st)) { continue; }

            ImGui::TableNextRow();

            // animated new/active row highlight
            if (st.animations) {
                float fade = 1.0f - (float)((now - f.uiActivity) / 1.3);
                if (fade > 0.0f) {
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, FadeAccent(st, fade));
                }
            }

            ImGui::TableSetColumnIndex(0);
            bool sel = (st.selectedFlow == f.flowId);
            char label[32];
            std::snprintf(label, sizeof(label), "%s##%llu",
                          KndFormatTime(f.firstTs).c_str(), (unsigned long long)f.flowId);
            if (ImGui::Selectable(label, sel, ImGuiSelectableFlags_SpanAllColumns)) {
                st.selectedFlow = f.flowId;
            }

            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(f.processName.empty() ? "(unknown)" : f.processName.c_str());
            if (ImGui::IsItemHovered() && !f.processPath.empty()) {
                ImGui::SetTooltip("%s", f.processPath.c_str());
            }

            ImGui::TableSetColumnIndex(2);
            ImGui::Text("%llu", (unsigned long long)f.processId);

            ImGui::TableSetColumnIndex(3);
            ImGui::TextUnformatted(KndFormatProto(f.protocol).c_str());

            ImGui::TableSetColumnIndex(4);
            ImGui::Text("%s:%u", KndFormatAddr(f.remoteAddr, f.ipVersion).c_str(), f.remotePort);

            ImGui::TableSetColumnIndex(5);
            ImGui::TextUnformatted(f.direction == KND_DIR_INBOUND ? "in" : "out");

            ImGui::TableSetColumnIndex(6);
            ImGui::TextUnformatted(KndFormatBytes(f.bytesOut).c_str());

            ImGui::TableSetColumnIndex(7);
            ImGui::TextUnformatted(KndFormatBytes(f.bytesIn).c_str());

            ImGui::TableSetColumnIndex(8);
            if (f.closed) {
                ImGui::TextColored(ImVec4(0.6f, 0.62f, 0.66f, 1.0f), "closed");
            } else {
                ImGui::TextColored(ImVec4(0.35f, 0.82f, 0.50f, 1.0f), "open");
            }
        }
        ImGui::EndTable();
    }
    ImGui::End();
}

static void DrawHexDump(const std::vector<uint8_t>& buf)
{
    const int perRow = 16;
    const int rows = (int)((buf.size() + perRow - 1) / perRow);

    ImGui::PushFont(nullptr); // keep default; monospace alignment via fixed widths
    ImGuiListClipper clipper;
    clipper.Begin(rows);
    while (clipper.Step()) {
        for (int r = clipper.DisplayStart; r < clipper.DisplayEnd; ++r) {
            size_t base = (size_t)r * perRow;
            char line[8];
            std::snprintf(line, sizeof(line), "%06zX", base);
            ImGui::TextColored(ImVec4(0.45f, 0.47f, 0.52f, 1.0f), "%s", line);
            ImGui::SameLine(0, 12);

            std::string hex, asc;
            hex.reserve(perRow * 3);
            asc.reserve(perRow);
            for (int c = 0; c < perRow; ++c) {
                size_t idx = base + c;
                if (idx < buf.size()) {
                    char hb[4];
                    std::snprintf(hb, sizeof(hb), "%02X ", buf[idx]);
                    hex += hb;
                    unsigned char ch = buf[idx];
                    asc += (ch >= 0x20 && ch < 0x7f) ? (char)ch : '.';
                } else {
                    hex += "   ";
                    asc += ' ';
                }
            }
            ImGui::TextUnformatted(hex.c_str());
            ImGui::SameLine(0, 12);
            ImGui::TextColored(ImVec4(0.70f, 0.74f, 0.55f, 1.0f), "%s", asc.c_str());
        }
    }
    clipper.End();
    ImGui::PopFont();
}

static ImVec4 StatusColor(int code)
{
    if (code >= 500) { return ImVec4(0.92f, 0.36f, 0.34f, 1.0f); }
    if (code >= 400) { return ImVec4(0.95f, 0.62f, 0.30f, 1.0f); }
    if (code >= 300) { return ImVec4(0.40f, 0.68f, 0.95f, 1.0f); }
    if (code >= 200) { return ImVec4(0.38f, 0.82f, 0.50f, 1.0f); }
    return ImVec4(0.70f, 0.72f, 0.76f, 1.0f);
}

static ImVec4 MethodColor(const std::string& m)
{
    if (m == "GET")  { return ImVec4(0.38f, 0.82f, 0.50f, 1.0f); }
    if (m == "POST") { return ImVec4(0.40f, 0.68f, 0.95f, 1.0f); }
    if (m == "PUT" || m == "PATCH") { return ImVec4(0.95f, 0.62f, 0.30f, 1.0f); }
    if (m == "DELETE") { return ImVec4(0.92f, 0.36f, 0.34f, 1.0f); }
    return ImVec4(0.75f, 0.77f, 0.80f, 1.0f);
}

static void DrawHeadersTable(const char* id, const std::vector<HttpHeader>& headers)
{
    if (headers.empty()) { ImGui::TextDisabled("(no headers)"); return; }
    const ImGuiTableFlags tf = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                               ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_Resizable;
    if (ImGui::BeginTable(id, 2, tf)) {
        ImGui::TableSetupColumn("Header", ImGuiTableColumnFlags_WidthStretch, 0.32f);
        ImGui::TableSetupColumn("Value",  ImGuiTableColumnFlags_WidthStretch, 0.68f);
        ImGui::TableHeadersRow();
        for (const auto& h : headers) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::TextUnformatted(h.name.c_str());
            ImGui::TableSetColumnIndex(1);
            ImGui::TextWrapped("%s", h.value.c_str());
        }
        ImGui::EndTable();
    }
}

static void DrawBody(const char* id, const HttpMessage& m)
{
    if (!m.contentEncoding.empty()) {
        ImGui::TextColored(ImVec4(0.95f, 0.62f, 0.30f, 1.0f),
                           "Content-Encoding: %s — %zu bytes (compressed; not decoded). See Raw tab.",
                           m.contentEncoding.c_str(), m.body.size());
        return;
    }
    if (m.body.empty()) { ImGui::TextDisabled("(no body)"); return; }

    if (HttpIsTextual(m.contentType) || m.contentType.empty()) {
        const size_t kShow = 256u * 1024u;
        const char* begin = m.body.data();
        const char* end = begin + (m.body.size() < kShow ? m.body.size() : kShow);
        ImGui::BeginChild(id, ImVec2(0, 220), ImGuiChildFlags_Borders, ImGuiWindowFlags_HorizontalScrollbar);
        ImGui::TextUnformatted(begin, end);   // clipped fast-path; no wrap keeps big bodies fast
        ImGui::EndChild();
        if (m.body.size() > kShow) {
            ImGui::TextDisabled("(showing first %zu KB of %zu bytes)", kShow / 1024, m.body.size());
        }
    } else {
        ImGui::TextDisabled("binary body, %zu bytes (%s) — see Raw tab",
                            m.body.size(), m.contentType.c_str());
    }
    if (m.bodyTruncated) {
        ImGui::TextColored(ImVec4(0.95f, 0.6f, 0.3f, 1.0f), "body truncated at the capture cap");
    }
}

static void DrawHttpMessage(const char* base, const HttpMessage& m, bool isReq)
{
    if (isReq) {
        ImGui::TextColored(MethodColor(m.method), "%s", m.method.c_str());
        ImGui::SameLine();
        ImGui::TextWrapped("%s", m.target.c_str());
        ImGui::TextDisabled("%s", m.version.c_str());
    } else {
        ImGui::TextColored(StatusColor(m.statusCode), "%d", m.statusCode);
        ImGui::SameLine();
        ImGui::TextUnformatted(m.statusReason.c_str());
        ImGui::SameLine();
        ImGui::TextDisabled("(%s)", m.version.c_str());
    }

    char hdrlabel[64];
    std::snprintf(hdrlabel, sizeof(hdrlabel), "Headers (%zu)##%shdr", m.headers.size(), base);
    if (ImGui::TreeNodeEx(hdrlabel, ImGuiTreeNodeFlags_DefaultOpen)) {
        char tid[40]; std::snprintf(tid, sizeof(tid), "%s_ht", base);
        DrawHeadersTable(tid, m.headers);
        ImGui::TreePop();
    }

    char bodylabel[64];
    std::snprintf(bodylabel, sizeof(bodylabel), "Body (%zu B)##%sbody", m.body.size(), base);
    if (ImGui::TreeNodeEx(bodylabel, ImGuiTreeNodeFlags_DefaultOpen)) {
        char bid[40]; std::snprintf(bid, sizeof(bid), "%s_bd", base);
        DrawBody(bid, m);
        ImGui::TreePop();
    }
}

static void RenderHttpTransactions(const char* idp, const std::vector<HttpMessage>& reqs,
                                   const std::vector<HttpMessage>& resps)
{
    size_t count = reqs.size() > resps.size() ? reqs.size() : resps.size();
    char childId[32];
    std::snprintf(childId, sizeof(childId), "%s_scroll", idp);
    ImGui::BeginChild(childId, ImVec2(0, 0));
    for (size_t i = 0; i < count; ++i) {
        char tx[96];
        if (i < reqs.size()) {
            std::snprintf(tx, sizeof(tx), "Transaction %zu  —  %s %s###%s%zu",
                          i + 1, reqs[i].method.c_str(), reqs[i].target.c_str(), idp, i);
        } else {
            std::snprintf(tx, sizeof(tx), "Transaction %zu###%s%zu", i + 1, idp, i);
        }
        if (ImGui::CollapsingHeader(tx, ImGuiTreeNodeFlags_DefaultOpen)) {
            char base[40];
            if (i < reqs.size()) {
                ImGui::SeparatorText("Request");
                std::snprintf(base, sizeof(base), "%srq%zu", idp, i);
                DrawHttpMessage(base, reqs[i], true);
            }
            if (i < resps.size()) {
                ImGui::SeparatorText("Response");
                std::snprintf(base, sizeof(base), "%srs%zu", idp, i);
                DrawHttpMessage(base, resps[i], false);
            }
        }
    }
    ImGui::EndChild();
}

static void DrawInspector(KndModel& model, AppState& st)
{
    if (!ImGui::Begin("Inspector")) { ImGui::End(); return; }

    KndFlow* f = model.find(st.selectedFlow);
    if (f == nullptr) {
        ImGui::TextDisabled("Select a connection to inspect.");
        ImGui::End();
        return;
    }

    ImGui::Text("%s  (pid %llu)", f->processName.empty() ? "(unknown)" : f->processName.c_str(),
                (unsigned long long)f->processId);
    ImGui::TextDisabled("%s  %s:%u  ->  %s:%u   |  out %s  in %s  %s",
                        KndFormatProto(f->protocol).c_str(),
                        KndFormatAddr(f->localAddr, f->ipVersion).c_str(), f->localPort,
                        KndFormatAddr(f->remoteAddr, f->ipVersion).c_str(), f->remotePort,
                        KndFormatBytes(f->bytesOut).c_str(), KndFormatBytes(f->bytesIn).c_str(),
                        f->closed ? "[closed]" : "[open]");
    ImGui::Separator();

    // Parse cache: only re-parse when the selected flow or its payload sizes change.
    static uint64_t cFlow = 0;
    static size_t   cOut = SIZE_MAX, cIn = SIZE_MAX;
    static std::vector<HttpMessage> reqs, resps;
    if (f->flowId != cFlow || f->payload[0].size() != cOut || f->payload[1].size() != cIn) {
        reqs  = HttpParse(f->payload[0], false);
        resps = HttpParse(f->payload[1], true);
        cFlow = f->flowId; cOut = f->payload[0].size(); cIn = f->payload[1].size();
    }

    if (ImGui::BeginTabBar("inspector_tabs")) {
        if (ImGui::BeginTabItem("HTTP")) {
            if (reqs.empty() && resps.empty()) {
                ImGui::TextDisabled("No HTTP detected in this stream.");
                ImGui::TextWrapped("Likely encrypted TLS or a non-HTTP protocol. Use the Raw tab for "
                                   "the bytes, or the Decrypted tab with a keylog loaded.");
            } else {
                RenderHttpTransactions("http", reqs, resps);
            }
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Decrypted")) {
            if (!st.keylogLoaded) {
                ImGui::TextDisabled("Load a keylog in the 'SChannel keys' panel to decrypt TLS 1.2 here.");
            } else {
                static uint64_t dFlow = 0;
                static size_t dOut = SIZE_MAX, dIn = SIZE_MAX, dKeys = SIZE_MAX;
                static TlsDecryptResult dres;
                static std::vector<HttpMessage> dreq, dresp;
                if (f->flowId != dFlow || f->payload[0].size() != dOut ||
                    f->payload[1].size() != dIn || st.keylog.size() != dKeys) {
                    dres = TlsDecryptFlow(f->payload[0], f->payload[1], st.keylog);
                    if (dres.ok) {
                        dreq = HttpParse(dres.outPlain, false);
                        dresp = HttpParse(dres.inPlain, true);
                    } else {
                        dreq.clear(); dresp.clear();
                    }
                    dFlow = f->flowId; dOut = f->payload[0].size();
                    dIn = f->payload[1].size(); dKeys = st.keylog.size();
                }
                if (!dres.ok) {
                    ImGui::TextColored(ImVec4(0.95f, 0.6f, 0.3f, 1.0f), "%s", dres.note.c_str());
                } else {
                    ImGui::TextDisabled("decrypted %zu B out / %zu B in  (suite 0x%04x)",
                                        dres.outPlain.size(), dres.inPlain.size(), dres.cipherSuite);
                    if (dreq.empty() && dresp.empty()) {
                        ImGui::BeginChild("dec_raw", ImVec2(0, 0), ImGuiChildFlags_Borders,
                                          ImGuiWindowFlags_HorizontalScrollbar);
                        if (!dres.outPlain.empty()) {
                            ImGui::TextDisabled("-> outbound");
                            ImGui::TextUnformatted((const char*)dres.outPlain.data(),
                                                   (const char*)dres.outPlain.data() + dres.outPlain.size());
                        }
                        if (!dres.inPlain.empty()) {
                            ImGui::TextDisabled("<- inbound");
                            ImGui::TextUnformatted((const char*)dres.inPlain.data(),
                                                   (const char*)dres.inPlain.data() + dres.inPlain.size());
                        }
                        ImGui::EndChild();
                    } else {
                        RenderHttpTransactions("dec", dreq, dresp);
                    }
                }
            }
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Raw")) {
            if (ImGui::BeginTabBar("raw_dir")) {
                const char* names[2] = { "Outbound", "Inbound" };
                for (int d = 0; d < 2; ++d) {
                    if (ImGui::BeginTabItem(names[d])) {
                        st.inspectorDir = d;
                        ImGui::TextDisabled("%s captured", KndFormatBytes(f->payload[d].size()).c_str());
                        if (f->truncated[d]) {
                            ImGui::SameLine();
                            ImGui::TextColored(ImVec4(0.95f, 0.6f, 0.3f, 1.0f),
                                               "(truncated at %d MB)", st.payloadCapMB);
                        }
                        ImGui::BeginChild("hex", ImVec2(0, 0), ImGuiChildFlags_Borders);
                        if (f->payload[d].empty()) {
                            ImGui::TextDisabled("(no payload captured for this direction)");
                        } else {
                            DrawHexDump(f->payload[d]);
                        }
                        ImGui::EndChild();
                        ImGui::EndTabItem();
                    }
                }
                ImGui::EndTabBar();
            }
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::End();
}

static bool InfoMatch(const std::string& info, const std::string& needleLower)
{
    if (needleLower.empty()) { return true; }
    std::string h = info;
    std::transform(h.begin(), h.end(), h.begin(), [](unsigned char c) { return (char)::tolower(c); });
    return h.find(needleLower) != std::string::npos;
}

static void DrawPackets(KndModel& model, AppState& st)
{
    if (!ImGui::Begin("Packets")) { ImGui::End(); return; }

    ImGui::SetNextItemWidth(260);
    ImGui::InputTextWithHint("##pf", "filter info (process / host / text)...",
                             st.packetFilter, sizeof(st.packetFilter));
    ImGui::SameLine();
    const auto& pkts = model.packets();
    ImGui::TextDisabled("(%zu packets)", pkts.size());

    std::string nf = st.packetFilter;
    std::transform(nf.begin(), nf.end(), nf.begin(), [](unsigned char c) { return (char)::tolower(c); });
    bool filtering = !nf.empty();

    std::vector<const KndPacket*> view;
    view.reserve(pkts.size());
    for (const auto& p : pkts) { if (!filtering || InfoMatch(p.info, nf)) { view.push_back(&p); } }

    ImGui::BeginChild("pkt_list", ImVec2(0, -170));
    const ImGuiTableFlags tf = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH |
                               ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable |
                               ImGuiTableFlags_SizingStretchProp;
    if (ImGui::BeginTable("packets", 6, tf)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("No.",  ImGuiTableColumnFlags_WidthFixed, 64);
        ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, 96);
        ImGui::TableSetupColumn("Flow", ImGuiTableColumnFlags_WidthFixed, 64);
        ImGui::TableSetupColumn("Dir",  ImGuiTableColumnFlags_WidthFixed, 40);
        ImGui::TableSetupColumn("Len",  ImGuiTableColumnFlags_WidthFixed, 64);
        ImGui::TableSetupColumn("Info", ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin((int)view.size());
        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                const KndPacket* p = view[i];
                ImGui::TableNextRow();
                if (p->type == KND_REC_CONN_OPEN) {
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, IM_COL32(40, 90, 50, 60));
                } else if (p->type == KND_REC_CONN_CLOSE) {
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, IM_COL32(70, 70, 70, 50));
                } else if (p->direction == KND_DIR_INBOUND) {
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, IM_COL32(40, 60, 90, 40));
                }

                ImGui::TableSetColumnIndex(0);
                char lbl[40];
                std::snprintf(lbl, sizeof(lbl), "%llu##p%llu",
                              (unsigned long long)p->no, (unsigned long long)p->no);
                bool sel = (st.selectedPacket == p->no);
                if (ImGui::Selectable(lbl, sel, ImGuiSelectableFlags_SpanAllColumns)) {
                    st.selectedPacket = p->no;
                }
                ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(KndFormatTime(p->ts).c_str());
                ImGui::TableSetColumnIndex(2); ImGui::Text("%04llX", (unsigned long long)(p->flowId & 0xFFFF));
                ImGui::TableSetColumnIndex(3);
                ImGui::TextUnformatted(p->type != KND_REC_DATA ? "" :
                                       (p->direction == KND_DIR_INBOUND ? "in" : "out"));
                ImGui::TableSetColumnIndex(4);
                if (p->type == KND_REC_DATA) { ImGui::Text("%u", p->length); }
                ImGui::TableSetColumnIndex(5); ImGui::TextUnformatted(p->info.c_str());
            }
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();

    ImGui::Separator();
    const KndPacket* selp = nullptr;
    for (const auto& p : pkts) { if (p.no == st.selectedPacket) { selp = &p; break; } }
    if (selp == nullptr) {
        ImGui::TextDisabled("Select a packet to see its bytes.");
    } else {
        ImGui::Text("#%llu  %s", (unsigned long long)selp->no, selp->info.c_str());
        if (!selp->preview.empty()) {
            ImGui::TextDisabled("preview (first %zu bytes; full stream in Inspector)", selp->preview.size());
            ImGui::BeginChild("pkt_hex", ImVec2(0, 0), ImGuiChildFlags_Borders);
            DrawHexDump(selp->preview);
            ImGui::EndChild();
        }
    }
    ImGui::End();
}

static void DrawStats(KndModel& model, KndClient& client, AppState& st)
{
    if (!ImGui::Begin("Statistics")) { ImGui::End(); return; }

    const KndModelStats& m = model.stats();
    const double now = ImGui::GetTime();

    if (now - st.lastThruTs >= 0.25) {
        double dt = (st.lastThruTs == 0.0) ? 0.25 : (now - st.lastThruTs);
        uint64_t cur = m.totalRecords;
        uint64_t curB = m.outBytes + m.inBytes;
        st.thru[st.thruHead]  = (float)((double)(cur - st.lastRecCount) / dt);
        st.thruB[st.thruHead] = (float)((double)(curB - st.lastByteCount) / dt);
        st.thruHead = (st.thruHead + 1) % IM_ARRAYSIZE(st.thru);
        st.lastRecCount = cur;
        st.lastByteCount = curB;
        st.lastThruTs = now;
    }
    int last = (st.thruHead + IM_ARRAYSIZE(st.thru) - 1) % IM_ARRAYSIZE(st.thru);

    ImGui::SeparatorText("Throughput");
    char ov[48];
    std::snprintf(ov, sizeof(ov), "%.0f rec/s", st.thru[last]);
    ImGui::PlotLines("##thru", st.thru, IM_ARRAYSIZE(st.thru), st.thruHead, ov, 0.0f, FLT_MAX, ImVec2(-1, 55));
    std::snprintf(ov, sizeof(ov), "%s/s", KndFormatBytes((uint64_t)st.thruB[last]).c_str());
    ImGui::PlotLines("##thruB", st.thruB, IM_ARRAYSIZE(st.thruB), st.thruHead, ov, 0.0f, FLT_MAX, ImVec2(-1, 55));

    ImGui::SeparatorText("Volume  (out / in)");
    uint64_t tot = m.outBytes + m.inBytes;
    float outFrac = tot ? (float)((double)m.outBytes / (double)tot) : 0.0f;
    ImGui::ProgressBar(outFrac, ImVec2(-1, 0), ("out " + KndFormatBytes(m.outBytes)).c_str());
    ImGui::ProgressBar(1.0f - outFrac, ImVec2(-1, 0), ("in  " + KndFormatBytes(m.inBytes)).c_str());

    ImGui::SeparatorText("Packet sizes");
    float hist[6];
    for (int i = 0; i < 6; ++i) { hist[i] = (float)m.sizeHist[i]; }
    ImGui::PlotHistogram("##sizes", hist, 6, 0, "<128  <512  <1500  <4k  <16k  16k+",
                         0.0f, FLT_MAX, ImVec2(-1, 55));

    const KND_RING_HEADER* ring = client.ring();
    if (ring != nullptr) {
        ImGui::SeparatorText("Kernel ring");
        uint64_t used = ring->writePos - ring->readPos;
        float fill = ring->dataSize ? (float)((double)used / (double)ring->dataSize) : 0.0f;
        ImGui::ProgressBar(fill, ImVec2(-1, 0),
                           (KndFormatBytes(used) + " / " + KndFormatBytes(ring->dataSize)).c_str());
        if (ring->droppedRecords > 0) {
            ImGui::TextColored(ImVec4(0.95f, 0.45f, 0.35f, 1.0f), "dropped %llu rec / %s",
                               (unsigned long long)ring->droppedRecords,
                               KndFormatBytes(ring->droppedBytes).c_str());
        }
    }

    ImGui::SeparatorText("Top talkers");
    const auto& flows = model.flows();
    std::vector<const KndFlow*> top;
    top.reserve(flows.size());
    for (auto& f : flows) { top.push_back(&f); }
    size_t showN = top.size() < 8 ? top.size() : 8;
    std::partial_sort(top.begin(), top.begin() + showN, top.end(),
        [](const KndFlow* a, const KndFlow* b) {
            return (a->bytesIn + a->bytesOut) > (b->bytesIn + b->bytesOut);
        });
    if (ImGui::BeginTable("talkers", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH |
                                         ImGuiTableFlags_SizingStretchProp)) {
        ImGui::TableSetupColumn("Process", ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableSetupColumn("Remote",  ImGuiTableColumnFlags_WidthStretch, 1.2f);
        ImGui::TableSetupColumn("Total",   ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableHeadersRow();
        for (size_t i = 0; i < showN; ++i) {
            const KndFlow* f = top[i];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::TextUnformatted(f->processName.empty() ? "(unknown)" : f->processName.c_str());
            ImGui::TableSetColumnIndex(1);
            ImGui::Text("%s:%u", KndFormatAddr(f->remoteAddr, f->ipVersion).c_str(), f->remotePort);
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(KndFormatBytes(f->bytesIn + f->bytesOut).c_str());
        }
        ImGui::EndTable();
    }

    ImGui::SeparatorText("Totals");
    ImGui::Text("records %llu   conns %llu/%llu   data %llu   payload %s",
                (unsigned long long)m.totalRecords, (unsigned long long)m.connOpens,
                (unsigned long long)m.connCloses, (unsigned long long)m.dataRecords,
                KndFormatBytes(m.payloadBytes).c_str());
    ImGui::End();
}

static void DrawSettings(AppState& st, KndClient& client)
{
    if (!ImGui::Begin("Settings")) { ImGui::End(); return; }

    ImGui::SeparatorText("Appearance");
    if (ImGui::ColorEdit3("Accent", st.accent, ImGuiColorEditFlags_NoInputs)) {
        Ui_ApplyTheme(st);
    }
    ImGui::SliderFloat("UI scale", &st.fontScale, 0.8f, 1.6f, "%.2f");
    ImGui::Checkbox("Animations", &st.animations);
    if (ImGui::Checkbox("Detach windows (multi-viewport)", &st.multiViewport)) {
        // applied in Ui_Frame against io.ConfigFlags
    }

    ImGui::SeparatorText("Capture");
    ImGui::SliderInt("Per-flow payload cap (MB)", &st.payloadCapMB, 1, 64);
    ImGui::Checkbox("Auto-scroll flows", &st.autoScroll);
    ImGui::Checkbox("Demo data (no driver needed)", &st.mockData);
    if (st.mockData) {
        ImGui::SameLine();
        ImGui::TextDisabled("(synthetic HTTP flows)");
    }

    ImGui::SeparatorText("Layout");
    if (ImGui::Button("Reset layout")) { st.askResetLayout = true; }
    ImGui::SameLine();
    ImGui::TextDisabled("settings are saved automatically on exit");

    ImGui::SeparatorText("Device");
    ImGui::TextWrapped("%s", st.status);
    if (ImGui::Button("Reconnect")) { Connect(client, st); }

    ImGui::End();
}

static void DrawMitm(AppState& st, KndClient& client, KndMitmCa& ca, KndMitmProxy& proxy)
{
    if (!ImGui::Begin("MITM")) { ImGui::End(); return; }

    ImGui::TextWrapped("True MITM: terminates TLS at a local proxy with a minted cert, so it "
                       "decrypts everything (incl. custom crypto) — but it's the detectable "
                       "method (rogue CA / cert pinning). VM only.");
    ImGui::Separator();

    st.mitmRunning = proxy.running();

    ImGui::BeginDisabled(st.mitmRunning);
    ImGui::SetNextItemWidth(120);
    ImGui::InputInt("Proxy port", &st.proxyPort);
    ImGui::EndDisabled();
    if (st.proxyPort < 1) { st.proxyPort = 1; }
    if (st.proxyPort > 65535) { st.proxyPort = 65535; }

    if (!st.mitmRunning) {
        if (ImGui::Button("Start MITM proxy", ImVec2(170, 0))) {
            std::string e;
            if (proxy.start((uint16_t)st.proxyPort, &ca, &e)) {
                snprintf(st.mitmStatus, sizeof(st.mitmStatus),
                         "MITM proxy: listening on 127.0.0.1:%d", st.proxyPort);
                if (st.useSystemProxy) {
                    std::string e2;
                    char hp[64];
                    snprintf(hp, sizeof(hp), "127.0.0.1:%d", st.proxyPort);
                    KndWin::SetSystemProxy(true, hp, e2);
                }
            } else {
                snprintf(st.mitmStatus, sizeof(st.mitmStatus), "start failed: %s", e.c_str());
            }
        }
    } else {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.70f, 0.22f, 0.24f, 0.55f));
        if (ImGui::Button("Stop MITM proxy", ImVec2(170, 0))) {
            proxy.stop();
            std::string e2;
            KndWin::SetSystemProxy(false, "", e2);
            snprintf(st.mitmStatus, sizeof(st.mitmStatus), "MITM proxy: stopped");
        }
        ImGui::PopStyleColor();
        ImGui::SameLine();
        ImGui::Text("conns %llu   active %llu",
                    (unsigned long long)proxy.connections(), (unsigned long long)proxy.active());
    }

    ImGui::Checkbox("Set as Windows system proxy while running", &st.useSystemProxy);
    if (ImGui::Checkbox("WFP transparent redirect (driver; no proxy settings)", &st.wfpRedirect)) {
        client.setRedirect(st.wfpRedirect, (uint16_t)st.proxyPort);
    }
    ImGui::SameLine();
    ImGui::TextDisabled("(needs the driver loaded)");
    ImGui::TextDisabled("%s", st.mitmStatus);

    ImGui::SeparatorText("Certificate authority");
    if (!ca.ready()) {
        ImGui::TextColored(ImVec4(0.95f, 0.55f, 0.30f, 1.0f), "CA not generated yet");
    } else {
        ImGui::TextDisabled("CA ready (knd_ca.pem). Clients must trust it, or pass it explicitly.");
    }
    if (ImGui::Button("Install CA to Root store (VM only)")) {
        std::string e;
        if (KndWin::InstallCaToRoot("knd_ca.pem", e)) {
            snprintf(st.caStatus, sizeof(st.caStatus), "CA: installed into LOCAL_MACHINE\\ROOT");
        } else {
            snprintf(st.caStatus, sizeof(st.caStatus), "CA install failed: %s", e.c_str());
        }
    }
    ImGui::TextDisabled("%s", st.caStatus);
    ImGui::TextWrapped("Test without installing: curl --proxy 127.0.0.1:%d --cacert knd_ca.pem "
                       "https://example.com", st.proxyPort);

    ImGui::End();
}

static void DrawStealth(AppState& st)
{
    if (!ImGui::Begin("SChannel keys")) { ImGui::End(); return; }

    ImGui::TextWrapped("Stealth decryption: pull TLS session keys from lsass (where SChannel derives "
                       "them) with NO hook in the analyzed app's process. Keys -> "
                       "C:\\ProgramData\\knd_sslkeys.log (SSLKEYLOGFILE format). VM ONLY.");
    ImGui::TextColored(ImVec4(0.95f, 0.55f, 0.30f, 1.0f),
                       "Needs admin + lsass NOT a PPL. Check:  reg query "
                       "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL");
    ImGui::Separator();

    std::wstring dll = KndInject::DefaultDllPath();
    if (ImGui::Button("Inject into lsass", ImVec2(170, 0))) {
        std::string e;
        unsigned long pid = KndInject::FindProcessId(L"lsass.exe");
        if (KndInject::InjectDll(pid, dll.c_str(), e)) {
            snprintf(st.stealthStatus, sizeof(st.stealthStatus),
                     "injected into lsass (pid %lu) - make TLS traffic, then check the keylog", pid);
        } else {
            snprintf(st.stealthStatus, sizeof(st.stealthStatus), "inject failed: %s", e.c_str());
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Unhook lsass", ImVec2(140, 0))) {
        std::string e;
        unsigned long pid = KndInject::FindProcessId(L"lsass.exe");
        if (KndInject::UnhookDll(pid, dll.c_str(), e)) {
            snprintf(st.stealthStatus, sizeof(st.stealthStatus), "unhooked + unloaded from lsass");
        } else {
            snprintf(st.stealthStatus, sizeof(st.stealthStatus), "unhook failed: %s", e.c_str());
        }
    }
    ImGui::TextDisabled("%s", st.stealthStatus);

    ImGui::Separator();
    ImGui::TextWrapped("First captures dump the key object to C:\\ProgramData\\knd_sslkeys_calib.log so "
                       "the master-secret offset can be confirmed for your Windows build. TLS 1.2 first; "
                       "1.3 once calibrated.");

    ImGui::SeparatorText("Offline decryption (keylog)");
    ImGui::SetNextItemWidth(320);
    ImGui::InputText("##keylogpath", st.keylogPath, sizeof(st.keylogPath));
    ImGui::SameLine();
    if (ImGui::Button("Load keylog")) {
        st.keylog = TlsKeyLog();
        st.keylog.loadFile(st.keylogPath);
        st.keylogLoaded = st.keylog.size() > 0;
        snprintf(st.keylogStatus, sizeof(st.keylogStatus), "keylog: %zu keys loaded", st.keylog.size());
    }
    ImGui::TextDisabled("%s  (drives the Inspector 'Decrypted' tab on TLS 1.2 flows)", st.keylogStatus);
    ImGui::End();
}

// ---------------------------------------------------------------- frame

void Ui_Frame(KndModel& model, KndClient& client, KndMitmCa& ca, KndMitmProxy& proxy, AppState& st)
{
    ImGuiIO& io = ImGui::GetIO();
    if (st.multiViewport) { io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable; }
    else                  { io.ConfigFlags &= ~ImGuiConfigFlags_ViewportsEnable; }
    io.FontGlobalScale = st.fontScale;
    model.payloadCap = (size_t)st.payloadCapMB * 1024u * 1024u;

    DrawMenuBar(st, client, model);

    ImGuiID dockId = ImGui::DockSpaceOverViewport(ImGui::GetID("KndDock"), ImGui::GetMainViewport());
    if (!st.layoutInitialized || st.resetLayout) {
        BuildDefaultLayout(dockId);
        st.layoutInitialized = true;
        st.resetLayout = false;
    }

    DrawControl(st, client, model);
    DrawFlows(model, st);
    DrawPackets(model, st);
    DrawInspector(model, st);
    DrawStats(model, client, st);
    DrawMitm(st, client, ca, proxy);
    DrawStealth(st);
    DrawSettings(st, client);

    // reset-layout confirmation
    if (st.askResetLayout) { ImGui::OpenPopup("Reset layout?"); st.askResetLayout = false; }
    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    if (ImGui::BeginPopupModal("Reset layout?", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextUnformatted("Discard the current window layout and restore the default?");
        ImGui::Separator();
        if (ImGui::Button("Yes, reset", ImVec2(120, 0))) {
            st.resetLayout = true;
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(120, 0))) { ImGui::CloseCurrentPopup(); }
        ImGui::EndPopup();
    }
}
