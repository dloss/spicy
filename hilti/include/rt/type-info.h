// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>
#include <string>
#include <variant>
#include <vector>

#include <hilti/rt/types/all.h>

namespace hilti::rt {

struct TypeInfo;

namespace type_info {

// Forward declare static, built-in type information objects.
extern TypeInfo bytes;
extern TypeInfo string;
extern TypeInfo int8;
extern TypeInfo int16;
extern TypeInfo int32;
extern TypeInfo int64;
extern TypeInfo uint8;
extern TypeInfo uint16;
extern TypeInfo uint32;
extern TypeInfo uint64;

namespace detail {

/** Base class for type-specific type information for types with atomic values.  */
template<typename T>
class AtomicType {
public:
    /** Casts a raw pointer to correctly typed reference. */
    const T& get(const void* ptr) const { return *static_cast<const T*>(ptr); }
};

/**
 * Base class for type-specific type information for types with contained
 * element of another type.
 */
class DereferencableType {
public:
    using Getter = std::function<const void*(const void*)>;
    DereferencableType(const TypeInfo* etype, Getter getter) : _etype(etype), _getter(getter) {}

    /**
     * Returns the type information for elements, as passed into the
     * constructor.
     */
    const TypeInfo* elementType() const { return _etype; }

    /**
     * Returns a raw pointer to the element, as well as its type information.
     */
    std::pair<const void*, const TypeInfo*> element(const void* p) const { return std::make_pair(_getter(p), _etype); }

private:
    const TypeInfo* _etype;
    const Getter _getter;
};

} // namespace detail

/** Describes a struct field. */
struct Field {
    Field(const char* name, const TypeInfo* type, std::ptrdiff_t offset) : name(name), type(type), offset(offset) {}

    std::string name;
    const TypeInfo* type;
    std::ptrdiff_t offset;
};

/** Type-specific information for `bytes`. */
class Bytes : public detail::AtomicType<hilti::rt::Bytes> {};

/** Type-specific information for signed integers. */
template<typename T>
class SignedInteger : public detail::AtomicType<T> {};

/** Type-specific information for unsigned integers. */
template<typename T>
class UnsignedInteger : public detail::AtomicType<T> {};

/** Type-specific information for `string`. */
class String : detail::AtomicType<std::string> {};

/** Type-specific information for `struct`. */
class Struct {
public:
    Struct(std::vector<Field> fields) : _fields(std::move(fields)) {}

    const auto& fields() const { return _fields; }

private:
    std::vector<Field> _fields;
};

/** Based class for type-specific information for `value_ref<T>. */
class ValueReference : public detail::DereferencableType {
public:
    using detail::DereferencableType::DereferencableType;
};

/** Type-specific information for particular instantiations of `value_ref<T>. */
template<typename T>
class ValueReferenceFor : public ValueReference {
public:
    ValueReferenceFor(const TypeInfo* etype)
        : ValueReference(etype,
                         [](const void* p) { return static_cast<const hilti::rt::ValueReference<T>*>(p)->get(); }) {}
};

} // namespace type_info

// clang-format off
/**
 * Top-level information describing one type. There's a generic part
 * applying to all types, plus a variant storing additional type-specific
 * information.
 */
struct TypeInfo {
    std::optional<std::string> id; /**< Spicy-side ID associated with the type, if any. */
    std::string display; /**< String rendering of the type. */

    /**
     * Type-specific additional information. This also acts as a tag
     * defining which kind of type is being described.
     */
    std::variant<
        type_info::Bytes,
        type_info::SignedInteger<int8_t>,
        type_info::SignedInteger<int16_t>,
        type_info::SignedInteger<int32_t>,
        type_info::SignedInteger<int64_t>,
        type_info::String,
        type_info::Struct,
        type_info::ValueReference,
        type_info::UnsignedInteger<uint8_t>,
        type_info::UnsignedInteger<uint16_t>,
        type_info::UnsignedInteger<uint32_t>,
        type_info::UnsignedInteger<uint64_t>
        > type;
};
// clang-format on

} // namespace hilti::rt
