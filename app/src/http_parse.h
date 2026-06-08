// http_parse.h - minimal, dependency-free HTTP/1.x parser over a captured byte
// stream (one direction). Handles multiple messages (keep-alive), Content-Length
// and chunked bodies. Compressed bodies (gzip/deflate/br) are left raw with the
// encoding noted (no decompression lib in Phase 1).
#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct HttpHeader {
    std::string name;
    std::string value;
};

struct HttpMessage {
    bool        isRequest = false;
    bool        valid     = false;

    // request line
    std::string method;
    std::string target;
    std::string version;

    // status line
    int         statusCode = 0;
    std::string statusReason;

    std::vector<HttpHeader> headers;

    std::string body;             // de-chunked; capped (see bodyTruncated)
    bool        chunked       = false;
    bool        bodyTruncated = false;
    size_t      bodyBytes     = 0;   // bytes of body observed
    std::string contentType;         // value of Content-Type (lowercased mime)
    std::string contentEncoding;     // gzip/deflate/br if present (body left raw)

    size_t      consumed = 0;        // bytes consumed from the buffer
};

// Parse 0..N messages from a one-direction buffer. asResponse selects the
// status-line vs request-line grammar.
std::vector<HttpMessage> HttpParse(const std::vector<uint8_t>& buf, bool asResponse);

// Case-insensitive header lookup; nullptr if absent.
const HttpHeader* HttpFindHeader(const HttpMessage& m, const char* name);

// True if the content-type looks like human-readable text we can show inline.
bool HttpIsTextual(const std::string& contentType);
