//
// Created by Vlad on 6/21/2024.
//

#pragma once
#include <span>
#include <cstdint>
#include <memory>
#include <string>
#include <expected>


namespace satsuma
{
    class Injector
    {
    public:
        [[nodiscard]]
        virtual std::expected<std::unique_ptr<uint8_t[]>, std::string>  InjectFromRaw(const std::span<uint8_t>& rawDll) const = 0;

        [[nodiscard]]
        virtual std::expected<std::unique_ptr<uint8_t[]>, std::string> InjectFromFile(const std::string& pathToDll) const = 0;

        virtual ~Injector() = default;
    };
}