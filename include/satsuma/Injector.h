//
// Created by Vlad on 6/21/2024.
//

#pragma once
#include <span>
#include <cstdint>
#include <memory>
#include <string>


namespace satsuma
{
    class Injector
    {
    public:
        [[nodiscard]]
        virtual std::unique_ptr<uint8_t[]>  InjectFromRaw(const std::span<uint8_t>& rawDll, const std::string& processName) const = 0;

        [[nodiscard]]
        virtual std::unique_ptr<uint8_t[]>  InjectFromFile(const std::string& pathToDll, const std::string& processName) const = 0;

        virtual ~Injector() = default;
    };
}