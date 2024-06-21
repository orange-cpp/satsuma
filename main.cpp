
#include <string>
#include <satsuma/Injector.h>
#include <satsuma/ManualMapInjector.h>
#include <thread>


int main()
{
    const std::string name = R"(C:\Users\Vlad\Downloads\hello-world-x64.dll)";
    auto dllHandle = satsuma::ManualMapInjector().InjectFromFile(name);
    std::this_thread::sleep_for(std::chrono::seconds(100));
    return 0;
}
