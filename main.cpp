#include <expected>
#include <fstream>
#include <iostream>
#include "Windows.h"
#include <string>
#include <satsuma/Injector.h>
#include <filesystem>
#include <satsuma/ManualMapInjector.h>
#include <thread>


int main()
{
    const std::string name = R"(C:\Users\Vlad\Downloads\hello-world-x64.dll)";

    std::vector<uint8_t> data(std::filesystem::file_size(name), 0);

    std::ifstream file(name, std::ios::binary);
    file.read(reinterpret_cast<char *>(data.data()), data.size());

    auto x = satsuma::ManualMapInjector().InjectFromRaw({data.data(), data.size()}, "");

    std::this_thread::sleep_for(std::chrono::seconds(100));
    return 0;
}
