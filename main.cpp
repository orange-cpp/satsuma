#include <satsuma/Injector.h>
#include <satsuma/ManualMapInjector.h>
#include <thread>
#include <satsuma/xorstr.h>
#include <CodeVirtualizer/StealthCodeArea.h>

STEALTH_AUX_FUNCTION
void stells()
{
    STEALTH_AREA_START
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_END
}

int main()
{
    VIRTUALIZER_START
    if ((uintptr_t)&main == 0x1)
        stells();
    VIRTUALIZER_END
    // C:\Users\Vlad\Downloads\hello-world-x64-with-exception.dll
    const char* name = R"(C:\Users\Vlad\Downloads\hello-world-x64-with-exception.dll)";
    try
    {
        auto dllHandle = satsuma::ManualMapInjector::InjectFromFile(name);
    }
    catch (...)
    {
        printf("catched orignal exception from other exe.");
    }
    std::this_thread::sleep_for(std::chrono::seconds(100));
    return 0;
}
