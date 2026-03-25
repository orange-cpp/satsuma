#include <Windows.h>
#include <cstdio>

// ---------------------------------------------------------------------------
// Static TLS test — __declspec(thread) variables must survive manual mapping
// ---------------------------------------------------------------------------
static __declspec(thread) int g_tlsCounter = 42;
static __declspec(thread) const char* g_tlsString = "hello from TLS";

static bool TestStaticTLS()
{
    printf("[test_dll] static TLS test\n");
    printf("  g_tlsCounter = %d (expected 42)\n", g_tlsCounter);
    printf("  g_tlsString  = \"%s\"\n", g_tlsString);

    if (g_tlsCounter != 42)
    {
        printf("  FAIL: g_tlsCounter mismatch\n");
        return false;
    }

    g_tlsCounter = 100;
    printf("  g_tlsCounter after write = %d (expected 100)\n", g_tlsCounter);

    if (g_tlsCounter != 100)
    {
        printf("  FAIL: g_tlsCounter write-back mismatch\n");
        return false;
    }

    printf("  PASS\n");
    return true;
}

// ---------------------------------------------------------------------------
// SEH exception test — structured exception handling must work
// ---------------------------------------------------------------------------
static bool TestSEH()
{
    printf("[test_dll] SEH exception test\n");

    bool caughtIt = false;
    __try
    {
        int* p = nullptr;
        *p = 0xDEAD; // access violation
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        caughtIt = true;
        printf("  caught access violation via SEH\n");
    }

    if (!caughtIt)
    {
        printf("  FAIL: exception was not caught\n");
        return false;
    }

    printf("  PASS\n");
    return true;
}

// ---------------------------------------------------------------------------
// C++ exception test
// ---------------------------------------------------------------------------
static bool TestCppException()
{
    printf("[test_dll] C++ exception test\n");

    bool caughtIt = false;
    try
    {
        throw 0xBEEF;
    }
    catch (int val)
    {
        caughtIt = true;
        printf("  caught C++ exception: 0x%X\n", val);
    }

    if (!caughtIt)
    {
        printf("  FAIL: C++ exception was not caught\n");
        return false;
    }

    printf("  PASS\n");
    return true;
}

// ---------------------------------------------------------------------------
// TLS callback — should fire before DllMain
// ---------------------------------------------------------------------------
static volatile bool g_tlsCallbackFired = false;

static void NTAPI TlsCallback(PVOID hModule, DWORD dwReason, PVOID pContext)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        g_tlsCallbackFired = true;
        printf("[test_dll] TLS callback fired (DLL_PROCESS_ATTACH)\n");
    }
}

#ifdef _MSC_VER
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma section(".CRT$XLB", read)
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK g_pfnTlsCallback = TlsCallback;
#else
__attribute__((section(".CRT$XLB"))) PIMAGE_TLS_CALLBACK g_pfnTlsCallback = TlsCallback;
#endif

// ---------------------------------------------------------------------------
// DllMain — entry point, runs all tests
// ---------------------------------------------------------------------------
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        printf("========================================\n");
        printf("[test_dll] DllMain DLL_PROCESS_ATTACH\n");
        printf("========================================\n");

        int passed = 0;
        int total = 4;

        // TLS callback should have already fired
        printf("[test_dll] TLS callback test\n");
        if (g_tlsCallbackFired)
        {
            printf("  PASS\n");
            passed++;
        }
        else
        {
            printf("  FAIL: TLS callback did not fire\n");
        }

        if (TestStaticTLS()) passed++;
        if (TestSEH()) passed++;
        if (TestCppException()) passed++;

        printf("========================================\n");
        printf("[test_dll] Results: %d/%d passed\n", passed, total);
        printf("========================================\n");
    }

    return TRUE;
}
