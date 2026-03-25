#include <cstdio>
#include <string>
#include "satsuma/ManualMapInjector.h"

int main(int argc, char* argv[])
{
    std::string dllPath = "test_dll.dll";
    std::string target  = "notepad.exe";

    if (argc > 1) dllPath = argv[1];
    if (argc > 2) target  = argv[2];

    printf("[remote_loader] Target: %s\n", target.c_str());

    DWORD pid = satsuma::ManualMapInjector::FindProcessId(target);
    if (!pid)
    {
        printf("[remote_loader] Process \"%s\" not found. Make sure it's running.\n", target.c_str());
        return 1;
    }

    printf("[remote_loader] Found PID: %lu\n", pid);
    printf("[remote_loader] Injecting: %s\n\n", dllPath.c_str());

    auto result = satsuma::ManualMapInjector::InjectRemoteFromFile(dllPath, target);

    if (!result)
    {
        printf("[remote_loader] FAILED: %s\n", result.error().c_str());
        return 1;
    }

    printf("[remote_loader] Success — remote image at 0x%llX\n",
           static_cast<unsigned long long>(result.value()));
    return 0;
}
