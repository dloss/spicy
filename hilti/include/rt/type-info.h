// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include "rt/types/bytes.h"
#include "rt/types/stream.h"
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include <hilti/rt/types/all.h>

namespace hilti::rt {

struct TypeInfo;

namespace type_info {

class Value {
public:
    Value(const void* ptr, const TypeInfo* ti) : _ptr(ptr), _ti(ti) {}

    auto pointer() const { return _ptr; }
    const auto& type() const { return *_ti; }

private:
    const void* _ptr;
    const TypeInfo* _ti;
};

// Forward declare static built-in type information objects.
extern TypeInfo address;
extern TypeInfo bool_;
extern TypeInfo bytes_iterator;
extern TypeInfo bytes;
extern TypeInfo bytes;
extern TypeInfo error;
extern TypeInfo int16;
extern TypeInfo int32;
extern TypeInfo int64;
extern TypeInfo int8;
extern TypeInfo interval;
extern TypeInfo network;
extern TypeInfo port;
extern TypeInfo real;
extern TypeInfo stream_iterator;
extern TypeInfo stream_view;
extern TypeInfo stream;
extern TypeInfo string;
extern TypeInfo string;
extern TypeInfo time;
extern TypeInfo uint16;
extern TypeInfo uint32;
extern TypeInfo uint64;
extern TypeInfo uint8;
extern TypeInfo void_;

namespace detail {

/** Base class for type-specific type information pertaining to types with atomic values.  */
template<typename T>
class AtomicType {
public:
    /** Casts a raw pointer to correctly typed reference. */
    const T& get(const Value& v) const { return *static_cast<const T*>(v.pointer()); }
};

/**
 * Base class for type-specific type information pertaining to types that contain an
 * element of another type.
 */
class DereferencableType {
public:
    using Accessor = std::function<const void*(const Value& v)>;
    DereferencableType(const TypeInfo* etype, Accessor accessor) : _etype(etype), _accessor(accessor) {}

    /**
     * Returns the type information for elements, as passed into the
     * constructor.
     */
    const TypeInfo* elementType() const { return _etype; }

    /**
     * Returns the dereferenced value.
     */
    Value element(const Value& v) const { return Value(_accessor(v), _etype); }

private:
    const TypeInfo* _etype;
    const Accessor _accessor;
};

class IterableType;

namespace iterable_type {
class Iterator {
public:
    Iterator(const IterableType* type, const Value& v);
    Iterator() {}

    Iterator& operator++();
    Value operator*() const;
    bool operator==(const Iterator& other) const {
        // This is good enough just for comparing against end().
        return _cur.has_value() == other._cur.has_value();
    }

    bool operator!=(const Iterator& other) const { return ! (*this == other); }

private:
    const IterableType* _type = nullptr;
    std::optional<std::any> _cur;
};

class Sequence {
public:
    using iterator = Iterator;
    using const_iterator = Iterator;

    Sequence(const IterableType* type, Value v) : _begin(type, std::move(v)) {}

    Iterator begin() const { return _begin; }
    Iterator end() const { return Iterator(); }

private:
    Iterator _begin;
};

} // namespace iterable_type

class IterableType {
public:
    using Accessor = std::tuple<std::function<std::optional<std::any>(const Value&)>,    // begin()
                                std::function<std::optional<std::any>(const std::any&)>, // next()
                                std::function<const void*(const std::any&)>>;            // deref()

    IterableType(const TypeInfo* etype, Accessor accessor) : _etype(etype), _accessor(std::move(accessor)) {}

    /**
     * Returns the type information for elements, as passed into the
     * constructor.
     */
    const TypeInfo* elementType() const { return _etype; }

    auto iterate(const Value& value) const { return iterable_type::Sequence(this, std::move(value)); }

private:
    friend class iterable_type::Iterator;
    const TypeInfo* _etype;
    Accessor _accessor;
};

namespace iterable_type {

inline Iterator::Iterator(const IterableType* type, const Value& v) : _type(type) {
    _cur = std::get<0>(_type->_accessor)(v); // begin
}

inline Iterator& Iterator::operator++() {
    if ( _cur.has_value() )
        _cur = std::get<1>(_type->_accessor)(*_cur); // next

    return *this;
}

inline Value Iterator::operator*() const {
    if ( ! _cur.has_value() )
        throw InvalidIterator("type info iterator invalid");

    return Value(std::get<2>(_type->_accessor)(*_cur), _type->_etype); // deref
}
} // namespace iterable_type

} // namespace detail

class Address : public detail::AtomicType<hilti::rt::Address> {};
class Bool : public detail::AtomicType<bool> {};
class Bytes : public detail::AtomicType<hilti::rt::Bytes> {};
class BytesIterator : public detail::AtomicType<hilti::rt::bytes::SafeConstIterator> {};
class Error : public detail::AtomicType<hilti::rt::result::Error> {};
class Interval : public detail::AtomicType<hilti::rt::Interval> {};
class Network : public detail::AtomicType<hilti::rt::Network> {};
class Port : public detail::AtomicType<hilti::rt::Port> {};
class Real : public detail::AtomicType<double> {};
class String : detail::AtomicType<std::string> {};
class Stream : public detail::AtomicType<hilti::rt::Stream> {};
class StreamIterator : public detail::AtomicType<hilti::rt::stream::SafeConstIterator> {};
class StreamView : public detail::AtomicType<hilti::rt::stream::View> {};
class Time : public detail::AtomicType<hilti::rt::Time> {};

template<typename Width>
class SignedInteger : public detail::AtomicType<Width> {};

class StrongReference : public detail::DereferencableType {
    template<typename T>
    StrongReference(const TypeInfo* etype)
        : detail::DereferencableType(etype, [](const void* p) {
              return static_cast<const hilti::rt::StrongReference<T>*>(p)->get();
          }) {}
};

namespace struct_ {

struct Field {
    Field(const char* name, const TypeInfo* type, std::ptrdiff_t offset) : name(name), type(type), offset(offset) {}

    std::string name;
    const TypeInfo* type;
    std::ptrdiff_t offset;
};

}; // namespace struct_

class Struct {
public:
    Struct(std::vector<struct_::Field> fields) : _fields(std::move(fields)) {}

    const auto& fields() const { return _fields; }

    auto iterate(const Value& v) const {
        std::vector<std::pair<const struct_::Field&, Value>> values;

        for ( const auto& f : _fields )
            values.emplace_back(f, Value(static_cast<const char*>(v.pointer()) + f.offset, f.type));

        return values;
    }

private:
    std::vector<struct_::Field> _fields;
};

template<typename Width>
class UnsignedInteger : public detail::AtomicType<Width> {};

class ValueReference : public detail::DereferencableType {
public:
    using detail::DereferencableType::DereferencableType;

    template<typename T>
    static auto accessor() {
        return [](const Value& v) -> const void* {
            return static_cast<const hilti::rt::ValueReference<T>*>(v.pointer())->get();
        };
    }
};

class Vector : public detail::IterableType {
public:
    using detail::IterableType::IterableType;

    template<typename T>
    using iterator_pair =
        std::pair<typename hilti::rt::Vector<T>::const_iterator, typename hilti::rt::Vector<T>::const_iterator>;

    template<typename T>
    static Accessor accessor() {
        return std::make_tuple(
            [](const Value& v_) -> std::optional<std::any> {
                auto v = static_cast<const hilti::rt::Vector<T>*>(v_.pointer());
                if ( v->cbegin() != v->cend() )
                    return make_pair(v->cbegin(), v->cend());
                else
                    return std::nullopt;
            },
            [](std::any i_) -> std::optional<std::any> {
                auto i = std::any_cast<iterator_pair<T>>(i_);
                auto n = std::make_pair(++i.first, i.second);
                if ( n.first != n.second )
                    return std::move(n);
                else
                    return std::nullopt;
            },
            [](std::any i_) -> const void* {
                auto i = std::any_cast<iterator_pair<T>>(i_);
                return &*i.first;
            });
    }

}; // namespace type_info

class Void {};

class WeakReference : public detail::DereferencableType {
    template<typename T>
    WeakReference(const TypeInfo* etype)
        : detail::DereferencableType(etype, [](const void* p) {
              return static_cast<const hilti::rt::WeakReference<T>*>(p)->get();
          }) {}
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
        type_info::Address,
        type_info::Bool,
        type_info::Bytes,
        type_info::BytesIterator,
        type_info::Interval,
        type_info::Network,
        type_info::Port,
        type_info::Real,
        type_info::SignedInteger<int16_t>,
        type_info::SignedInteger<int32_t>,
        type_info::SignedInteger<int64_t>,
        type_info::SignedInteger<int8_t>,
        type_info::Stream,
        type_info::StreamIterator,
        type_info::StreamView,
        type_info::String,
        type_info::StrongReference,
        type_info::Struct,
        type_info::Time,
        type_info::UnsignedInteger<uint16_t>,
        type_info::UnsignedInteger<uint32_t>,
        type_info::UnsignedInteger<uint64_t>,
        type_info::UnsignedInteger<uint8_t>,
        type_info::ValueReference,
        type_info::Vector,
        type_info::Void,
        type_info::WeakReference
        > type;
};
// clang-format on

} // namespace hilti::rt
