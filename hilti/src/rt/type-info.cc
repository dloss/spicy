// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <cinttypes>

#include <hilti/rt/type-info.h>

using namespace hilti::rt;

TypeInfo type_info::bytes = {std::nullopt, "bytes", type_info::Bytes()};
TypeInfo type_info::string = {std::nullopt, "string", type_info::String()};
TypeInfo type_info::int8 = {std::nullopt, "int8", type_info::SignedInteger<int8_t>()};
TypeInfo type_info::int16 = {std::nullopt, "int16", type_info::SignedInteger<int16_t>()};
TypeInfo type_info::int32 = {std::nullopt, "int32", type_info::SignedInteger<int32_t>()};
TypeInfo type_info::int64 = {std::nullopt, "int64", type_info::SignedInteger<int64_t>()};
TypeInfo type_info::uint8 = {std::nullopt, "uint8", type_info::UnsignedInteger<uint8_t>()};
TypeInfo type_info::uint16 = {std::nullopt, "uint16", type_info::UnsignedInteger<uint16_t>()};
TypeInfo type_info::uint32 = {std::nullopt, "uint32", type_info::UnsignedInteger<uint32_t>()};
TypeInfo type_info::uint64 = {std::nullopt, "uint64", type_info::UnsignedInteger<uint64_t>()};
