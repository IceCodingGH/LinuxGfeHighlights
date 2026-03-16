#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

static const char *get_log_path(void) {
    static int initialized = 0;
    static char path[MAX_PATH];
    DWORD n = 0;

    if (initialized) {
        return path;
    }
    initialized = 1;

    n = GetEnvironmentVariableA("GFE_SHIM_LOG_FILE", path, (DWORD)sizeof(path));
    if (n > 0 && n < sizeof(path)) {
        return path;
    }

    n = GetTempPathA((DWORD)sizeof(path), path);
    if (n == 0 || n >= sizeof(path)) {
        strcpy(path, "C:\\gfe_shim.log");
        return path;
    }

    strncat(path, "gfe_shim.log", sizeof(path) - strlen(path) - 1);
    return path;
}

static void log_line(const char *fmt, ...) {
    FILE *f = NULL;
    SYSTEMTIME st;
    va_list ap;

    f = fopen(get_log_path(), "a");
    if (!f) {
        return;
    }

    GetLocalTime(&st);
    fprintf(
        f,
        "%04u-%02u-%02u %02u:%02u:%02u.%03u ",
        st.wYear,
        st.wMonth,
        st.wDay,
        st.wHour,
        st.wMinute,
        st.wSecond,
        st.wMilliseconds
    );

    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
}

static int env_truthy(const char *name) {
    char buf[32];
    DWORD n = GetEnvironmentVariableA(name, buf, (DWORD)sizeof(buf));
    if (n == 0 || n >= sizeof(buf)) {
        return 0;
    }
    switch (buf[0]) {
        case '1':
        case 'y':
        case 'Y':
        case 't':
        case 'T':
            return 1;
        default:
            return 0;
    }
}

static int is_readable_protect(DWORD protect) {
    DWORD p = protect & 0xFF;
    if (p == PAGE_READONLY || p == PAGE_READWRITE || p == PAGE_WRITECOPY) {
        return 1;
    }
    if (p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY) {
        return 1;
    }
    return 0;
}

static size_t safe_copy_bytes(void *dst, size_t dst_cap, const void *src, size_t want) {
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t start = 0;
    uintptr_t end = 0;
    size_t can = 0;

    if (!dst || dst_cap == 0 || !src || want == 0) {
        return 0;
    }

    if (VirtualQuery(src, &mbi, sizeof(mbi)) == 0) {
        return 0;
    }
    if (mbi.State != MEM_COMMIT) {
        return 0;
    }
    if ((mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) {
        return 0;
    }
    if (!is_readable_protect(mbi.Protect)) {
        return 0;
    }

    start = (uintptr_t)src;
    end = (uintptr_t)mbi.BaseAddress + (uintptr_t)mbi.RegionSize;
    if (end <= start) {
        return 0;
    }
    can = (size_t)(end - start);
    if (can > dst_cap) {
        can = dst_cap;
    }
    if (can > want) {
        can = want;
    }

    memcpy(dst, src, can);
    return can;
}

static void log_bytes(const char *label, const void *ptr) {
    unsigned char buf[64];
    char hex[sizeof(buf) * 2 + 1];
    size_t n = 0;

    if (!ptr) {
        log_line("%s ptr=NULL", label);
        return;
    }

    n = safe_copy_bytes(buf, sizeof(buf), ptr, sizeof(buf));
    if (n == 0) {
        log_line("%s ptr=%p unreadable", label, ptr);
        return;
    }

    for (size_t i = 0; i < n; i++) {
        static const char *digits = "0123456789abcdef";
        hex[i * 2 + 0] = digits[(buf[i] >> 4) & 0xF];
        hex[i * 2 + 1] = digits[buf[i] & 0xF];
    }
    hex[n * 2] = '\0';
    log_line("%s ptr=%p bytes=%zu hex=%s", label, ptr, n, hex);
}

static LONG g_wsa_state = 0; /* 0=uninit, 1=initing, 2=ready, 3=failed */
static SOCKET g_udp_sock = INVALID_SOCKET;
static struct sockaddr_in g_udp_addr;
static LONG g_udp_enable_cached = -1;

static int udp_enabled(void) {
    LONG cached = InterlockedCompareExchange(&g_udp_enable_cached, -1, -1);
    if (cached != -1) {
        return cached ? 1 : 0;
    }
    cached = env_truthy("GFE_SHIM_SEND_UDP") ? 1 : 0;
    InterlockedExchange(&g_udp_enable_cached, cached);
    return cached ? 1 : 0;
}

static int ensure_udp_sender(void) {
    LONG state = InterlockedCompareExchange(&g_wsa_state, 1, 0);
    WSADATA wsa;

    if (state == 2) return 1;
    if (state == 3) return 0;
    if (state == 1) {
        for (int i = 0; i < 1000; i++) {
            if (InterlockedCompareExchange(&g_wsa_state, 1, 1) == 2) return 1;
            Sleep(1);
        }
        return 0;
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        InterlockedExchange(&g_wsa_state, 3);
        return 0;
    }

    g_udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g_udp_sock == INVALID_SOCKET) {
        InterlockedExchange(&g_wsa_state, 3);
        return 0;
    }

    memset(&g_udp_addr, 0, sizeof(g_udp_addr));
    g_udp_addr.sin_family = AF_INET;
    g_udp_addr.sin_port = htons(31337);
    g_udp_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    /* Intentionally never call WSACleanup(). */
    InterlockedExchange(&g_wsa_state, 2);
    return 1;
}

static void emit_event(const char *event_name) {
    const char *payload = event_name ? event_name : "highlight";
    char line[256];
    log_line("event=%s", payload);

    if (!udp_enabled()) {
        return;
    }
    if (!ensure_udp_sender()) {
        return;
    }

    snprintf(line, sizeof(line), "%s\n", payload);
    sendto(
        g_udp_sock,
        line,
        (int)strlen(line),
        0,
        (const struct sockaddr *)&g_udp_addr,
        sizeof(g_udp_addr)
    );
}

/*
 * Many integrations call NVGSDK_Create to obtain a function table and then call
 * through those pointers (not via exported NVGSDK_* symbols). If we return a
 * zeroed blob, the caller will typically treat it as "unsupported" and skip
 * registration entirely.
 */
#define NVG_TABLE_SLOTS 64

#define DEFINE_NVG_TBL_STUB(idx) \
    static int64_t WINAPI nvg_tbl_fn_##idx(void *self, void *a1, void *a2, void *a3, void *a4) { \
        (void)self; (void)a1; (void)a2; (void)a3; (void)a4; \
        log_line("NVGSDK table fn[%d] called", (idx)); \
        /* Keep UDP noise low: only log to file by default. */ \
        return 0; \
    }

DEFINE_NVG_TBL_STUB(0)
DEFINE_NVG_TBL_STUB(1)
DEFINE_NVG_TBL_STUB(2)
DEFINE_NVG_TBL_STUB(3)
DEFINE_NVG_TBL_STUB(4)
DEFINE_NVG_TBL_STUB(5)
DEFINE_NVG_TBL_STUB(6)
DEFINE_NVG_TBL_STUB(7)
DEFINE_NVG_TBL_STUB(8)
DEFINE_NVG_TBL_STUB(9)
DEFINE_NVG_TBL_STUB(10)
DEFINE_NVG_TBL_STUB(11)
DEFINE_NVG_TBL_STUB(12)
DEFINE_NVG_TBL_STUB(13)
DEFINE_NVG_TBL_STUB(14)
DEFINE_NVG_TBL_STUB(15)
DEFINE_NVG_TBL_STUB(16)
DEFINE_NVG_TBL_STUB(17)
DEFINE_NVG_TBL_STUB(18)
DEFINE_NVG_TBL_STUB(19)
DEFINE_NVG_TBL_STUB(20)
DEFINE_NVG_TBL_STUB(21)
DEFINE_NVG_TBL_STUB(22)
DEFINE_NVG_TBL_STUB(23)
DEFINE_NVG_TBL_STUB(24)
DEFINE_NVG_TBL_STUB(25)
DEFINE_NVG_TBL_STUB(26)
DEFINE_NVG_TBL_STUB(27)
DEFINE_NVG_TBL_STUB(28)
DEFINE_NVG_TBL_STUB(29)
DEFINE_NVG_TBL_STUB(30)
DEFINE_NVG_TBL_STUB(31)
DEFINE_NVG_TBL_STUB(32)
DEFINE_NVG_TBL_STUB(33)
DEFINE_NVG_TBL_STUB(34)
DEFINE_NVG_TBL_STUB(35)
DEFINE_NVG_TBL_STUB(36)
DEFINE_NVG_TBL_STUB(37)
DEFINE_NVG_TBL_STUB(38)
DEFINE_NVG_TBL_STUB(39)
DEFINE_NVG_TBL_STUB(40)
DEFINE_NVG_TBL_STUB(41)
DEFINE_NVG_TBL_STUB(42)
DEFINE_NVG_TBL_STUB(43)
DEFINE_NVG_TBL_STUB(44)
DEFINE_NVG_TBL_STUB(45)
DEFINE_NVG_TBL_STUB(46)
DEFINE_NVG_TBL_STUB(47)
DEFINE_NVG_TBL_STUB(48)
DEFINE_NVG_TBL_STUB(49)
DEFINE_NVG_TBL_STUB(50)
DEFINE_NVG_TBL_STUB(51)
DEFINE_NVG_TBL_STUB(52)
DEFINE_NVG_TBL_STUB(53)
DEFINE_NVG_TBL_STUB(54)
DEFINE_NVG_TBL_STUB(55)
DEFINE_NVG_TBL_STUB(56)
DEFINE_NVG_TBL_STUB(57)
DEFINE_NVG_TBL_STUB(58)
DEFINE_NVG_TBL_STUB(59)
DEFINE_NVG_TBL_STUB(60)
DEFINE_NVG_TBL_STUB(61)
DEFINE_NVG_TBL_STUB(62)
DEFINE_NVG_TBL_STUB(63)

static void fill_nvg_table(void **tbl, size_t slots) {
    /* Fill with non-NULL pointers so callers that only "probe" don't bail out. */
    if (slots < NVG_TABLE_SLOTS) {
        /* still fill what we have */
    }

    tbl[0]  = (void *)&nvg_tbl_fn_0;
    tbl[1]  = (void *)&nvg_tbl_fn_1;
    tbl[2]  = (void *)&nvg_tbl_fn_2;
    tbl[3]  = (void *)&nvg_tbl_fn_3;
    tbl[4]  = (void *)&nvg_tbl_fn_4;
    tbl[5]  = (void *)&nvg_tbl_fn_5;
    tbl[6]  = (void *)&nvg_tbl_fn_6;
    tbl[7]  = (void *)&nvg_tbl_fn_7;
    tbl[8]  = (void *)&nvg_tbl_fn_8;
    tbl[9]  = (void *)&nvg_tbl_fn_9;
    tbl[10] = (void *)&nvg_tbl_fn_10;
    tbl[11] = (void *)&nvg_tbl_fn_11;
    tbl[12] = (void *)&nvg_tbl_fn_12;
    tbl[13] = (void *)&nvg_tbl_fn_13;
    tbl[14] = (void *)&nvg_tbl_fn_14;
    tbl[15] = (void *)&nvg_tbl_fn_15;
    tbl[16] = (void *)&nvg_tbl_fn_16;
    tbl[17] = (void *)&nvg_tbl_fn_17;
    tbl[18] = (void *)&nvg_tbl_fn_18;
    tbl[19] = (void *)&nvg_tbl_fn_19;
    tbl[20] = (void *)&nvg_tbl_fn_20;
    tbl[21] = (void *)&nvg_tbl_fn_21;
    tbl[22] = (void *)&nvg_tbl_fn_22;
    tbl[23] = (void *)&nvg_tbl_fn_23;
    tbl[24] = (void *)&nvg_tbl_fn_24;
    tbl[25] = (void *)&nvg_tbl_fn_25;
    tbl[26] = (void *)&nvg_tbl_fn_26;
    tbl[27] = (void *)&nvg_tbl_fn_27;
    tbl[28] = (void *)&nvg_tbl_fn_28;
    tbl[29] = (void *)&nvg_tbl_fn_29;
    tbl[30] = (void *)&nvg_tbl_fn_30;
    tbl[31] = (void *)&nvg_tbl_fn_31;
    tbl[32] = (void *)&nvg_tbl_fn_32;
    tbl[33] = (void *)&nvg_tbl_fn_33;
    tbl[34] = (void *)&nvg_tbl_fn_34;
    tbl[35] = (void *)&nvg_tbl_fn_35;
    tbl[36] = (void *)&nvg_tbl_fn_36;
    tbl[37] = (void *)&nvg_tbl_fn_37;
    tbl[38] = (void *)&nvg_tbl_fn_38;
    tbl[39] = (void *)&nvg_tbl_fn_39;
    tbl[40] = (void *)&nvg_tbl_fn_40;
    tbl[41] = (void *)&nvg_tbl_fn_41;
    tbl[42] = (void *)&nvg_tbl_fn_42;
    tbl[43] = (void *)&nvg_tbl_fn_43;
    tbl[44] = (void *)&nvg_tbl_fn_44;
    tbl[45] = (void *)&nvg_tbl_fn_45;
    tbl[46] = (void *)&nvg_tbl_fn_46;
    tbl[47] = (void *)&nvg_tbl_fn_47;
    tbl[48] = (void *)&nvg_tbl_fn_48;
    tbl[49] = (void *)&nvg_tbl_fn_49;
    tbl[50] = (void *)&nvg_tbl_fn_50;
    tbl[51] = (void *)&nvg_tbl_fn_51;
    tbl[52] = (void *)&nvg_tbl_fn_52;
    tbl[53] = (void *)&nvg_tbl_fn_53;
    tbl[54] = (void *)&nvg_tbl_fn_54;
    tbl[55] = (void *)&nvg_tbl_fn_55;
    tbl[56] = (void *)&nvg_tbl_fn_56;
    tbl[57] = (void *)&nvg_tbl_fn_57;
    tbl[58] = (void *)&nvg_tbl_fn_58;
    tbl[59] = (void *)&nvg_tbl_fn_59;
    tbl[60] = (void *)&nvg_tbl_fn_60;
    tbl[61] = (void *)&nvg_tbl_fn_61;
    tbl[62] = (void *)&nvg_tbl_fn_62;
    tbl[63] = (void *)&nvg_tbl_fn_63;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    (void)hinst;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        /* Don't do any I/O, networking, or library init here (loader-lock). */
        DisableThreadLibraryCalls(hinst);
    }
    return TRUE;
}

__declspec(dllexport) int WINAPI GfeSDK_Init(void *config, void *callbacks) {
    (void)config;
    (void)callbacks;
    log_line("GfeSDK_Init called");
    emit_event("gfe_init");
    return 0;
}

__declspec(dllexport) int WINAPI GfeSDK_Shutdown(void) {
    log_line("GfeSDK_Shutdown called");
    emit_event("gfe_shutdown");
    return 0;
}

__declspec(dllexport) int WINAPI GfeSDK_IsAvailable(void) {
    log_line("GfeSDK_IsAvailable called");
    emit_event("gfe_is_available");
    return 1;
}

__declspec(dllexport) int WINAPI GfeSDK_OpenGroup(void *group_desc) {
    (void)group_desc;
    log_line("GfeSDK_OpenGroup called");
    log_bytes("GfeSDK_OpenGroup group_desc", group_desc);
    emit_event("gfe_open_group");
    return 0;
}

__declspec(dllexport) int WINAPI GfeSDK_CloseGroup(void) {
    log_line("GfeSDK_CloseGroup called");
    emit_event("gfe_close_group");
    return 0;
}

__declspec(dllexport) int WINAPI GfeSDK_SetVideoHighlight(void *highlight_desc) {
    (void)highlight_desc;
    log_line("GfeSDK_SetVideoHighlight called");
    log_bytes("GfeSDK_SetVideoHighlight highlight_desc", highlight_desc);
    emit_event("video_highlight");
    return 0;
}

__declspec(dllexport) int WINAPI GfeSDK_SetScreenshotHighlight(void *highlight_desc) {
    (void)highlight_desc;
    log_line("GfeSDK_SetScreenshotHighlight called");
    log_bytes("GfeSDK_SetScreenshotHighlight highlight_desc", highlight_desc);
    emit_event("screenshot_highlight");
    return 0;
}

__declspec(dllexport) int WINAPI GfeSDK_SaveHighlights(void) {
    log_line("GfeSDK_SaveHighlights called");
    emit_event("save_highlights");
    return 0;
}

__declspec(dllexport) void *WINAPI NVGSDK_Create(void) {
    void **table = NULL;
    log_line("NVGSDK_Create called");
    emit_event("nvg_create");

    /*
     * Return a table of function pointers. This matches a common pattern where
     * the plugin reads and calls through returned pointers.
     */
    table = (void **)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, NVG_TABLE_SLOTS * sizeof(void *));
    if (!table) {
        return (void *)1; /* last resort: non-NULL sentinel */
    }
    fill_nvg_table((void **)table, NVG_TABLE_SLOTS);
    return (void *)table;
}

__declspec(dllexport) void WINAPI NVGSDK_Destroy(void *handle) {
    log_line("NVGSDK_Destroy called handle=%p", handle);
    emit_event("nvg_destroy");
    if (handle && handle != (void *)1) {
        HeapFree(GetProcessHeap(), 0, handle);
    }
}

__declspec(dllexport) int WINAPI NVGSDK_Init(void) {
    log_line("NVGSDK_Init called");
    emit_event("nvg_init");
    return 0;
}

__declspec(dllexport) int WINAPI NVGSDK_Initialize(void *config, void *callbacks) {
    (void)config;
    (void)callbacks;
    log_line("NVGSDK_Initialize called");
    emit_event("nvg_initialize");
    return 0;
}

__declspec(dllexport) int WINAPI NVGSDK_Shutdown(void) {
    log_line("NVGSDK_Shutdown called");
    emit_event("nvg_shutdown");
    return 0;
}

__declspec(dllexport) int WINAPI NVGSDK_IsAvailable(void) {
    log_line("NVGSDK_IsAvailable called");
    emit_event("nvg_is_available");
    return 1;
}

__declspec(dllexport) int WINAPI NVGSDK_OpenGroup(void *group_desc) {
    (void)group_desc;
    log_line("NVGSDK_OpenGroup called");
    log_bytes("NVGSDK_OpenGroup group_desc", group_desc);
    emit_event("nvg_open_group");
    return 0;
}

__declspec(dllexport) int WINAPI NVGSDK_CloseGroup(void) {
    log_line("NVGSDK_CloseGroup called");
    emit_event("nvg_close_group");
    return 0;
}

__declspec(dllexport) int WINAPI NVGSDK_SetVideoHighlight(void *highlight_desc) {
    (void)highlight_desc;
    log_line("NVGSDK_SetVideoHighlight called");
    log_bytes("NVGSDK_SetVideoHighlight highlight_desc", highlight_desc);
    emit_event("video_highlight");
    return 0;
}

__declspec(dllexport) int WINAPI NVGSDK_SetScreenshotHighlight(void *highlight_desc) {
    (void)highlight_desc;
    log_line("NVGSDK_SetScreenshotHighlight called");
    log_bytes("NVGSDK_SetScreenshotHighlight highlight_desc", highlight_desc);
    emit_event("screenshot_highlight");
    return 0;
}

__declspec(dllexport) int WINAPI NVGSDK_SaveHighlights(void) {
    log_line("NVGSDK_SaveHighlights called");
    emit_event("save_highlights");
    return 0;
}

__declspec(dllexport) int WINAPI NVGSDK_RegisterEvent(void *event_desc) {
    (void)event_desc;
    log_line("NVGSDK_RegisterEvent called");
    log_bytes("NVGSDK_RegisterEvent event_desc", event_desc);
    emit_event("register_event");
    return 0;
}

__declspec(dllexport) int WINAPI NVGSDK_Poll(void) {
    /* Games commonly call this every frame; avoid per-call file I/O spam. */
    static ULONGLONG last_log_ms = 0;
    ULONGLONG now_ms = GetTickCount64();
    if (now_ms - last_log_ms >= 1000) {
        last_log_ms = now_ms;
        log_line("NVGSDK_Poll called (rate-limited)");
    }
    return 0;
}

__declspec(dllexport) int WINAPI NVGSDK_Highlights_ConfigureAsync(
    void *session,
    void *config,
    void *callback,
    void *user_data
) {
    (void)session;
    (void)config;
    (void)callback;
    (void)user_data;
    log_line(
        "NVGSDK_Highlights_ConfigureAsync called session=%p config=%p callback=%p user=%p",
        session,
        config,
        callback,
        user_data
    );
    log_bytes("NVGSDK_Highlights_ConfigureAsync config", config);
    emit_event("highlights_configure_async");
    return 0;
}

__declspec(dllexport) int WINAPI NVGSDK_Highlights_OpenGroup(void *group_desc) {
    (void)group_desc;
    log_line("NVGSDK_Highlights_OpenGroup called");
    log_bytes("NVGSDK_Highlights_OpenGroup group_desc", group_desc);
    emit_event("nvg_open_group");
    return 0;
}

__declspec(dllexport) int WINAPI NVGSDK_Highlights_OpenGroupAsync(
    void *session,
    void *group_desc,
    void *callback,
    void *user_data
) {
    (void)session;
    (void)callback;
    (void)user_data;
    log_line(
        "NVGSDK_Highlights_OpenGroupAsync called session=%p group_desc=%p callback=%p user=%p",
        session,
        group_desc,
        callback,
        user_data
    );
    log_bytes("NVGSDK_Highlights_OpenGroupAsync group_desc", group_desc);
    emit_event("nvg_open_group_async");
    return 0;
}

__declspec(dllexport) int WINAPI NVGSDK_Highlights_CloseGroup(void) {
    log_line("NVGSDK_Highlights_CloseGroup called");
    emit_event("nvg_close_group");
    return 0;
}

__declspec(dllexport) int WINAPI NVGSDK_Highlights_SetVideoHighlight(void *highlight_desc) {
    (void)highlight_desc;
    log_line("NVGSDK_Highlights_SetVideoHighlight called");
    log_bytes("NVGSDK_Highlights_SetVideoHighlight highlight_desc", highlight_desc);
    emit_event("video_highlight");
    return 0;
}

__declspec(dllexport) int WINAPI NVGSDK_Highlights_SetVideoHighlightAsync(
    void *session,
    void *highlight_desc,
    void *callback,
    void *user_data
) {
    (void)session;
    (void)callback;
    (void)user_data;
    log_line(
        "NVGSDK_Highlights_SetVideoHighlightAsync called session=%p highlight_desc=%p callback=%p user=%p",
        session,
        highlight_desc,
        callback,
        user_data
    );
    log_bytes("NVGSDK_Highlights_SetVideoHighlightAsync highlight_desc", highlight_desc);
    emit_event("video_highlight_async");
    return 0;
}

__declspec(dllexport) int WINAPI NVGSDK_Highlights_SetScreenshotHighlight(void *highlight_desc) {
    (void)highlight_desc;
    log_line("NVGSDK_Highlights_SetScreenshotHighlight called");
    log_bytes("NVGSDK_Highlights_SetScreenshotHighlight highlight_desc", highlight_desc);
    emit_event("screenshot_highlight");
    return 0;
}

__declspec(dllexport) int WINAPI NVGSDK_Highlights_SetScreenshotHighlightAsync(
    void *session,
    void *highlight_desc,
    void *callback,
    void *user_data
) {
    (void)session;
    (void)callback;
    (void)user_data;
    log_line(
        "NVGSDK_Highlights_SetScreenshotHighlightAsync called session=%p highlight_desc=%p callback=%p user=%p",
        session,
        highlight_desc,
        callback,
        user_data
    );
    log_bytes("NVGSDK_Highlights_SetScreenshotHighlightAsync highlight_desc", highlight_desc);
    emit_event("screenshot_highlight_async");
    return 0;
}

__declspec(dllexport) int WINAPI NVGSDK_Highlights_SaveHighlights(void) {
    log_line("NVGSDK_Highlights_SaveHighlights called");
    emit_event("save_highlights");
    return 0;
}

__declspec(dllexport) int WINAPI NVGSDK_RequestPermissionsAsync(
    void *session,
    void *permissions_desc,
    void *callback,
    void *user_data
) {
    (void)session;
    (void)permissions_desc;
    (void)callback;
    (void)user_data;
    log_line(
        "NVGSDK_RequestPermissionsAsync called session=%p permissions_desc=%p callback=%p user=%p",
        session,
        permissions_desc,
        callback,
        user_data
    );
    log_bytes("NVGSDK_RequestPermissionsAsync permissions_desc", permissions_desc);
    emit_event("request_permissions_async");
    return 0;
}
