#include <cstdio>
#include <string>
#include "satsuma/ManualMapInjector.h"

int main(int argc, char* argv[])
{
    std::string dllPath = "test_dll.dll";
    if (argc > 1)
        dllPath = argv[1];

    printf("[loader] Manual-mapping: %s\n\n", dllPath.c_str());

    auto result = satsuma::ManualMapInjector::InjectFromFile(dllPath);

    if (!result)
    {
        printf("[loader] FAILED: %s\n", result.error().c_str());
        return 1;
    }

    printf("\n[loader] Success — image loaded at %p\n", result.value().get());
    return 0;
}
