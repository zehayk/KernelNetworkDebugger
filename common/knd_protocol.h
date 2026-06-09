/*
 * knd_protocol.h - Shared contract between the kernel driver and the usermode app.
 *
 * This single header is the ONE source of truth for: device naming, IOCTL codes,
 * the shared ring-buffer layout, and the wire format of every record the driver
 * produces. Both sides include it; if it changes, bump KND_PROTOCOL_VERSION.
 *
 * Include AFTER the platform base header so CTL_CODE / METHOD_* / FILE_*_ACCESS
 * and the base integer typedefs are available:
 *      kernel   -> <ntddk.h> or <wdm.h>
 *      usermode -> <windows.h> then <winioctl.h>
 *
 * Design notes:
 *  - The driver is the SINGLE producer; the app is the SINGLE consumer (SPSC).
 *    No locks are needed across the boundary, only acquire/release ordering on
 *    the two monotonic positions in KND_RING_HEADER.
 *  - The producer MUST NOT block. If the ring is full it drops the newest record
 *    and bumps the dropped* counters; the kernel thread never waits on the app.
 *  - Records are never split across the wrap point. If a record would not fit in
 *    the contiguous space before end-of-buffer, the producer writes a KND_REC_WRAP
 *    pad record filling the remainder and restarts at offset 0. So every record is
 *    physically contiguous and can be cast straight to its struct.
 */

#ifndef KND_PROTOCOL_H
#define KND_PROTOCOL_H

/* Platform base types/macros this contract relies on (CTL_CODE, METHOD_*,
 * DECLSPEC_ALIGN, C_ASSERT, the integer typedefs). The kernel driver TU includes
 * <ntddk.h>/<wdm.h> before us and the WDK defines _KERNEL_MODE; usermode pulls in
 * the Win32 headers here so app code can include this contract directly without
 * worrying about include order. */
#if !defined(_KERNEL_MODE)
#  include <windows.h>
#  include <winioctl.h>
#endif

#define KND_PROTOCOL_VERSION   1u
#define KND_DRIVER_VERSION     1u   /* bump on driver behavior changes */

/* ------------------------------------------------------------------ *
 *  Device naming
 *  NOTE: these names are a static fingerprint. For "stealth" builds they
 *  should be randomized at build time (see docs/stealth.md). Kept readable
 *  during development.
 * ------------------------------------------------------------------ */
#define KND_DEVICE_NAME    L"\\Device\\KndCap"
#define KND_SYMLINK_NAME   L"\\??\\KndCap"
#define KND_DOS_NAME       L"\\\\.\\KndCap"     /* CreateFileW path (usermode) */

/* ------------------------------------------------------------------ *
 *  IOCTLs
 *  Device type sits in the vendor-custom FILE_DEVICE_UNKNOWN range.
 * ------------------------------------------------------------------ */
#define KND_DEVICE_TYPE    0x8013
#define KND_IOCTL(fn, method, access) CTL_CODE(KND_DEVICE_TYPE, (fn), (method), (access))

#define IOCTL_KND_GET_VERSION    KND_IOCTL(0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KND_MAP_RING       KND_IOCTL(0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KND_UNMAP_RING     KND_IOCTL(0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KND_START_CAPTURE  KND_IOCTL(0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KND_STOP_CAPTURE   KND_IOCTL(0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KND_GET_STATS      KND_IOCTL(0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
/* Enable/disable WFP transparent connect-redirect of outbound :443/:80 to the
 * local MITM proxy (no system proxy settings). IN = KND_REDIRECT_IN. */
#define IOCTL_KND_SET_REDIRECT   KND_IOCTL(0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
/* Scoped physical read/write of the driver's OWN cache region only.
 * 'offset' is an offset into the mapped cache region, NOT an arbitrary PA.
 * The driver validates 0 <= offset, offset+length <= totalSize, length <= KND_MAX_PHYS_RW,
 * then translates that kernel VA to a PA per-page (nonpaged pool is not physically
 * contiguous) before touching memory. Anything outside the cache is rejected.
 * This deliberately is NOT an arbitrary phys R/W primitive (that is a BYOVD class bug). */
#define IOCTL_KND_PHYS_READ      KND_IOCTL(0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KND_PHYS_WRITE     KND_IOCTL(0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* ------------------------------------------------------------------ *
 *  Sizes / limits
 * ------------------------------------------------------------------ */
#define KND_RING_MAGIC             0x52444E4Bu   /* 'K','N','D','R' little-endian */
#define KND_RING_DATA_OFFSET       0x1000u       /* data area begins page-aligned */
#define KND_DEFAULT_RING_DATA_SIZE (32u * 1024u * 1024u) /* 32 MiB, must be power of two */
#define KND_MAX_DATA_CHUNK         (64u * 1024u) /* payload bytes per KND_REC_DATA record */
#define KND_MAX_PHYS_RW            4096u         /* max bytes per scoped phys R/W IOCTL */
#define KND_PROCPATH_CHARS         260u          /* inline image-path cap (truncated) */
#define KND_RECORD_ALIGN           8u

/* ------------------------------------------------------------------ *
 *  Record types / enums (defines, not C enums, to fix the wire size)
 * ------------------------------------------------------------------ */
#define KND_REC_WRAP        0u  /* padding to end of buffer; skip 'length' bytes */
#define KND_REC_CONN_OPEN   1u  /* payload: KND_CONN_PAYLOAD */
#define KND_REC_CONN_CLOSE  2u  /* payload: KND_CONN_PAYLOAD (bytesIn/Out valid) */
#define KND_REC_DATA        3u  /* payload: KND_DATA_PAYLOAD + raw bytes */

#define KND_DIR_OUTBOUND    0u
#define KND_DIR_INBOUND     1u

#define KND_PROTO_TCP       6u
#define KND_PROTO_UDP       17u

#define KND_IPV4            4u
#define KND_IPV6            6u

#define KND_DATA_CIPHERTEXT 0u  /* raw on-wire bytes (TLS or unknown) */
#define KND_DATA_PLAINTEXT  1u  /* decrypted/decoded (later phases) */

/* ------------------------------------------------------------------ *
 *  Ring buffer header. Lives at the base of the mapped region; the data
 *  area starts at KND_RING_DATA_OFFSET. Producer- and consumer-owned
 *  fields are on separate cache lines to avoid false sharing.
 * ------------------------------------------------------------------ */
#pragma pack(push, 8)

typedef struct DECLSPEC_ALIGN(64) _KND_RING_HEADER {
    ULONG     magic;        /* KND_RING_MAGIC */
    ULONG     version;      /* KND_PROTOCOL_VERSION */
    ULONG     headerSize;   /* == KND_RING_DATA_OFFSET */
    ULONG     dataSize;     /* bytes in the data area (power of two) */
    ULONGLONG totalSize;    /* headerSize + dataSize == mapped region size */
    ULONGLONG reservedHdr;

    /* ---- producer-owned (driver writes, app reads) ---- */
    DECLSPEC_ALIGN(64)
    volatile ULONGLONG writePos;        /* monotonic count of bytes produced */
    volatile ULONGLONG totalRecords;
    volatile ULONGLONG totalBytes;
    volatile ULONGLONG droppedRecords;  /* records discarded because ring was full */
    volatile ULONGLONG droppedBytes;
    volatile ULONG     captureActive;   /* 1 while capture is running */
    volatile ULONG     activeFlows;

    /* ---- consumer-owned (app writes, driver reads) ---- */
    DECLSPEC_ALIGN(64)
    volatile ULONGLONG readPos;         /* monotonic count of bytes consumed */
} KND_RING_HEADER;

/* Common record prefix. 'length' covers this header + payload, rounded up to
 * KND_RECORD_ALIGN. Cast the bytes right after this struct to the payload type. */
typedef struct _KND_RECORD {
    ULONG     length;     /* total record size incl. header, multiple of 8 */
    USHORT    type;       /* KND_REC_* */
    USHORT    flags;
    ULONGLONG sequence;   /* monotonic per-record id */
    LONGLONG  timestamp;  /* 100ns ticks since 1601 (KeQuerySystemTimePrecise) */
} KND_RECORD;

/* Payload for KND_REC_CONN_OPEN / KND_REC_CONN_CLOSE. */
typedef struct _KND_CONN_PAYLOAD {
    ULONGLONG flowId;        /* driver-assigned, stable for the connection's life */
    ULONGLONG processId;
    UCHAR     protocol;      /* KND_PROTO_* */
    UCHAR     ipVersion;     /* KND_IPV4 / KND_IPV6 */
    UCHAR     direction;     /* KND_DIR_* at connection establishment */
    UCHAR     reserved0;
    USHORT    localPort;     /* host byte order */
    USHORT    remotePort;    /* host byte order */
    UCHAR     localAddr[16]; /* network order; IPv4 occupies [0..3] */
    UCHAR     remoteAddr[16];
    ULONGLONG bytesIn;       /* valid on CONN_CLOSE */
    ULONGLONG bytesOut;      /* valid on CONN_CLOSE */
    USHORT    processPathChars; /* WCHARs used in processPath (excl. terminator) */
    USHORT    reserved1;
    ULONG     reserved2;
    WCHAR     processPath[KND_PROCPATH_CHARS]; /* image path, truncated if longer */
} KND_CONN_PAYLOAD;

/* Payload for KND_REC_DATA. 'dataLength' raw bytes follow this struct; the whole
 * record is then padded up to KND_RECORD_ALIGN. */
typedef struct _KND_DATA_PAYLOAD {
    ULONGLONG flowId;
    UCHAR     direction;   /* KND_DIR_* */
    UCHAR     dataKind;    /* KND_DATA_CIPHERTEXT / KND_DATA_PLAINTEXT */
    USHORT    reserved0;
    ULONG     dataLength;  /* bytes of payload immediately following */
    /* UCHAR data[dataLength]; */
} KND_DATA_PAYLOAD;

/* ------------------------------------------------------------------ *
 *  IOCTL in/out payloads
 * ------------------------------------------------------------------ */

typedef struct _KND_VERSION_OUT {
    ULONG protocolVersion;
    ULONG driverVersion;
} KND_VERSION_OUT;

/* OUT for IOCTL_KND_MAP_RING: where the ring was mapped in the caller's space. */
typedef struct _KND_MAP_RING_OUT {
    ULONGLONG userVa;      /* base of the mapping in the caller's address space */
    ULONGLONG totalSize;   /* bytes mapped (== KND_RING_HEADER.totalSize) */
    ULONG     dataOffset;  /* == KND_RING_DATA_OFFSET */
    ULONG     dataSize;
} KND_MAP_RING_OUT;

/* IN for IOCTL_KND_SET_REDIRECT. */
typedef struct _KND_REDIRECT_IN {
    ULONG  enable;       /* 0/1 */
    USHORT proxyPort;    /* host byte order */
    USHORT reserved;
} KND_REDIRECT_IN;

/* The localRedirectContext the driver attaches to a redirected connection; the
 * proxy reads it back via SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT to recover the
 * original destination it must connect to. */
typedef struct _KND_REDIRECT_CTX {
    UCHAR  ipVersion;     /* KND_IPV4 / KND_IPV6 */
    UCHAR  reserved;
    USHORT origPort;      /* host byte order */
    UCHAR  origAddr[16];  /* network order; IPv4 in [0..3] */
} KND_REDIRECT_CTX;

typedef struct _KND_STATS_OUT {
    ULONGLONG writePos;
    ULONGLONG readPos;
    ULONGLONG totalRecords;
    ULONGLONG droppedRecords;
    ULONGLONG totalBytes;
    ULONGLONG droppedBytes;
    ULONG     activeFlows;
    ULONG     captureActive;
} KND_STATS_OUT;

/* IN for IOCTL_KND_PHYS_READ (struct only) and IOCTL_KND_PHYS_WRITE (struct
 * immediately followed by 'length' data bytes in the same input buffer).
 * For READ, the output buffer receives 'length' raw bytes. */
typedef struct _KND_PHYS_RW {
    ULONGLONG offset;    /* offset into the cache region, [0, totalSize) */
    ULONG     length;    /* bytes, <= KND_MAX_PHYS_RW */
    ULONG     reserved;
    /* write only: UCHAR data[length]; */
} KND_PHYS_RW;

#pragma pack(pop)

/* ------------------------------------------------------------------ *
 *  Compile-time layout guarantees (binary contract)
 * ------------------------------------------------------------------ */
C_ASSERT((sizeof(KND_RECORD) % KND_RECORD_ALIGN) == 0);
C_ASSERT(sizeof(KND_RECORD) == 24);
C_ASSERT((KND_RING_DATA_OFFSET % 0x1000u) == 0);
C_ASSERT(sizeof(KND_RING_HEADER) <= KND_RING_DATA_OFFSET);
C_ASSERT((sizeof(KND_CONN_PAYLOAD) % KND_RECORD_ALIGN) == 0);
C_ASSERT((sizeof(KND_DATA_PAYLOAD) % KND_RECORD_ALIGN) == 0);
C_ASSERT(KND_MAX_PHYS_RW <= 0x10000u);

/* Helper: round a size up to record alignment (usable in both C and C++). */
#define KND_ALIGN_UP(n) (((n) + (KND_RECORD_ALIGN - 1)) & ~((ULONGLONG)(KND_RECORD_ALIGN - 1)))

#endif /* KND_PROTOCOL_H */
