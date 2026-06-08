// http_parse.cpp - see http_parse.h.
#include "http_parse.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>

namespace {

constexpr size_t kMaxMessages = 64;       // stop after this many per direction
constexpr size_t kMaxBody     = 1u << 20; // cap stored body at 1 MiB

std::string Lower(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

std::string Trim(const std::string& s)
{
    size_t a = 0, b = s.size();
    while (a < b && (unsigned char)s[a] <= ' ') { ++a; }
    while (b > a && (unsigned char)s[b - 1] <= ' ') { --b; }
    return s.substr(a, b - a);
}

size_t FindCRLF(const uint8_t* d, size_t n, size_t from)
{
    for (size_t i = from; i + 2 <= n; ++i) {
        if (d[i] == '\r' && d[i + 1] == '\n') { return i; }
    }
    return SIZE_MAX;
}

size_t FindDoubleCRLF(const uint8_t* d, size_t n, size_t from)
{
    for (size_t i = from; i + 4 <= n; ++i) {
        if (d[i] == '\r' && d[i + 1] == '\n' && d[i + 2] == '\r' && d[i + 3] == '\n') { return i; }
    }
    return SIZE_MAX;
}

bool LooksLikeStartLine(const uint8_t* d, size_t n, size_t off, bool asResponse)
{
    if (off >= n) { return false; }
    if (asResponse) {
        return (off + 5 <= n) && std::memcmp(d + off, "HTTP/", 5) == 0;
    }
    // request: first token must be an uppercase-ish method token followed by a space
    unsigned char c = d[off];
    return std::isalpha(c) != 0;
}

// Append chunk data, honoring the global body cap.
void AppendCapped(std::string& body, const uint8_t* p, size_t len, bool& truncated)
{
    if (body.size() >= kMaxBody) { truncated = true; return; }
    size_t room = kMaxBody - body.size();
    size_t take = std::min(len, room);
    body.append(reinterpret_cast<const char*>(p), take);
    if (take < len) { truncated = true; }
}

bool ParseOne(const uint8_t* d, size_t n, size_t& off, bool asResponse, HttpMessage& m)
{
    if (!LooksLikeStartLine(d, n, off, asResponse)) { return false; }

    size_t hdrEnd = FindDoubleCRLF(d, n, off);
    if (hdrEnd == SIZE_MAX) { return false; } // headers not fully captured yet

    const std::string head(reinterpret_cast<const char*>(d + off), hdrEnd - off);

    // ---- start line ----
    size_t lineEnd = head.find("\r\n");
    std::string startLine = head.substr(0, lineEnd == std::string::npos ? head.size() : lineEnd);
    m.isRequest = !asResponse;

    if (asResponse) {
        // HTTP/x.y CODE REASON
        size_t s1 = startLine.find(' ');
        if (s1 == std::string::npos) { return false; }
        m.version = startLine.substr(0, s1);
        size_t s2 = startLine.find(' ', s1 + 1);
        std::string code = startLine.substr(s1 + 1, (s2 == std::string::npos ? startLine.size() : s2) - s1 - 1);
        m.statusCode = std::atoi(code.c_str());
        if (s2 != std::string::npos) { m.statusReason = startLine.substr(s2 + 1); }
        if (m.statusCode < 100 || m.statusCode > 599) { return false; }
    } else {
        // METHOD TARGET HTTP/x.y
        size_t s1 = startLine.find(' ');
        if (s1 == std::string::npos) { return false; }
        m.method = startLine.substr(0, s1);
        size_t s2 = startLine.find(' ', s1 + 1);
        if (s2 == std::string::npos) { return false; }
        m.target = startLine.substr(s1 + 1, s2 - s1 - 1);
        m.version = startLine.substr(s2 + 1);
        if (m.version.compare(0, 5, "HTTP/") != 0) { return false; }
    }

    // ---- headers ----
    size_t pos = (lineEnd == std::string::npos) ? head.size() : lineEnd + 2;
    while (pos < head.size()) {
        size_t le = head.find("\r\n", pos);
        std::string line = head.substr(pos, (le == std::string::npos ? head.size() : le) - pos);
        pos = (le == std::string::npos) ? head.size() : le + 2;
        if (line.empty()) { break; }
        size_t colon = line.find(':');
        if (colon == std::string::npos) { continue; }
        HttpHeader h;
        h.name = Trim(line.substr(0, colon));
        h.value = Trim(line.substr(colon + 1));
        std::string ln = Lower(h.name);
        if (ln == "content-type")          { m.contentType = Lower(h.value); }
        else if (ln == "content-encoding") { m.contentEncoding = Lower(h.value); }
        else if (ln == "transfer-encoding" && Lower(h.value).find("chunked") != std::string::npos) {
            m.chunked = true;
        }
        m.headers.push_back(std::move(h));
    }

    // ---- body ----
    size_t bodyStart = hdrEnd + 4;
    const HttpHeader* cl = HttpFindHeader(m, "Content-Length");

    if (m.chunked) {
        size_t p = bodyStart;
        for (;;) {
            size_t le = FindCRLF(d, n, p);
            if (le == SIZE_MAX) { m.bodyTruncated = true; p = n; break; }
            std::string sizeLine(reinterpret_cast<const char*>(d + p), le - p);
            size_t semi = sizeLine.find(';');
            if (semi != std::string::npos) { sizeLine = sizeLine.substr(0, semi); }
            unsigned long chunk = std::strtoul(Trim(sizeLine).c_str(), nullptr, 16);
            p = le + 2;
            if (chunk == 0) {
                size_t end = FindCRLF(d, n, p);          // optional trailers then blank line
                p = (end == SIZE_MAX) ? n : end + 2;
                break;
            }
            if (p + chunk > n) { AppendCapped(m.body, d + p, n - p, m.bodyTruncated); p = n; break; }
            AppendCapped(m.body, d + p, chunk, m.bodyTruncated);
            p += chunk;
            if (p + 2 <= n && d[p] == '\r' && d[p + 1] == '\n') { p += 2; }
        }
        m.bodyBytes = m.body.size();
        off = p;
    } else if (cl != nullptr) {
        unsigned long len = std::strtoul(cl->value.c_str(), nullptr, 10);
        size_t avail = n - bodyStart;
        size_t take = (len < avail) ? len : avail;
        AppendCapped(m.body, d + bodyStart, take, m.bodyTruncated);
        if (take < len) { m.bodyTruncated = true; }
        m.bodyBytes = take;
        off = bodyStart + take;
    } else if (asResponse) {
        // no length: body runs to end of captured data (connection-close framing)
        AppendCapped(m.body, d + bodyStart, n - bodyStart, m.bodyTruncated);
        m.bodyBytes = n - bodyStart;
        off = n;
    } else {
        m.bodyBytes = 0;
        off = bodyStart;
    }

    m.valid = true;
    m.consumed = off;
    return true;
}

} // namespace

const HttpHeader* HttpFindHeader(const HttpMessage& m, const char* name)
{
    std::string want = Lower(name);
    for (const auto& h : m.headers) {
        if (Lower(h.name) == want) { return &h; }
    }
    return nullptr;
}

bool HttpIsTextual(const std::string& ct)
{
    if (ct.empty()) { return false; }
    static const char* kTextual[] = {
        "text/", "application/json", "application/xml", "application/javascript",
        "application/x-www-form-urlencoded", "application/xhtml", "+json", "+xml", "application/graphql"
    };
    for (const char* t : kTextual) {
        if (ct.find(t) != std::string::npos) { return true; }
    }
    return false;
}

std::vector<HttpMessage> HttpParse(const std::vector<uint8_t>& buf, bool asResponse)
{
    std::vector<HttpMessage> out;
    if (buf.empty()) { return out; }

    const uint8_t* d = buf.data();
    size_t n = buf.size();
    size_t off = 0;

    while (off < n && out.size() < kMaxMessages) {
        while (off < n && (d[off] == '\r' || d[off] == '\n')) { ++off; } // skip blank separators
        if (off >= n) { break; }
        HttpMessage m;
        size_t start = off;
        if (!ParseOne(d, n, off, asResponse, m)) { break; }
        out.push_back(std::move(m));
        if (off <= start) { break; } // safety against non-advancing parse
    }
    return out;
}
