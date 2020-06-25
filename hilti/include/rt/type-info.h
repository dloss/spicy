// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include "rt/fmt.h"
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

    operator bool() const { return _ptr != nullptr; }

private:
    const void* _ptr;
    const TypeInfo* _ti;
};

// Forward declare static built-in type information objects.
extern TypeInfo address;
extern TypeInfo any;
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
extern TypeInfo library;
extern TypeInfo network;
extern TypeInfo port;
extern TypeInfo real;
extern TypeInfo regexp;
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
    DereferencableType(const TypeInfo* vtype, Accessor accessor) : _vtype(vtype), _accessor(accessor) {}

    /**
     * Returns the type information for elements, as passed into the
     * constructor.
     */
    const TypeInfo* valueType() const { return _vtype; }

    /**
     * Returns the dereferenced value.
     */
    Value value(const Value& v) const { return Value(_accessor(v), _vtype); }

private:
    const TypeInfo* _vtype;
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


/** Base class for type-specific type information pertaining to types that do not carry a value. */
class ValueLessType {};


/**
 * Base class for type-specific type information pertaining to types for which we do not yet have implemented their
 * full type information.
 */
class NotImplementedType {};

} // namespace detail

//////

class Address : public detail::AtomicType<hilti::rt::Address> {};

class Any : public detail::ValueLessType {};

class Bool : public detail::AtomicType<bool> {};

class Bytes : public detail::AtomicType<hilti::rt::Bytes> {};

class BytesIterator : public detail::AtomicType<hilti::rt::bytes::Iterator> {};

namespace enum_ {

struct Label {
    Label(std::string id, int64_t value) : id(std::move(id)), value(value) {}

    std::string id;
    int64_t value;
};

} // namespace enum_

class Enum {
public:
    Enum(std::vector<enum_::Label> labels) : _labels(std::move(labels)) {}

    const auto& labels() const { return _labels; }

    enum_::Label get(const Value& v) const {
        auto n = *static_cast<const uint64_t*>(v.pointer());

        for ( const auto& l : _labels ) {
            if ( n == l.value )
                return l;
        }

        return enum_::Label(fmt("<unknown-%" PRIu64 ">", n), n);
    }

private:
    std::vector<enum_::Label> _labels;
};


class Error : public detail::AtomicType<hilti::rt::result::Error> {};

class Exception : public detail::AtomicType<hilti::rt::Exception> {};

class Function : public detail::NotImplementedType {};

class Interval : public detail::AtomicType<hilti::rt::Interval> {};

class Library : public detail::ValueLessType {};

class Map : public detail::IterableType {
public:
    using detail::IterableType::IterableType;

    template<typename K, typename V>
    using iterator_pair =
        std::pair<typename hilti::rt::Map<K, V>::const_iterator, typename hilti::rt::Map<K, V>::const_iterator>;

    template<typename K, typename V>
    static Accessor accessor() {
        return std::make_tuple(
            [](const Value& v_) -> std::optional<std::any> { // begin
                auto v = static_cast<const hilti::rt::Map<K, V>*>(v_.pointer());
                if ( v->cbegin() != v->cend() )
                    return make_pair(v->cbegin(), v->cend());
                else
                    return std::nullopt;
            },
            [](std::any i_) -> std::optional<std::any> { // next
                auto i = std::any_cast<iterator_pair<K, V>>(i_);
                auto n = std::make_pair(++i.first, i.second);
                if ( n.first != n.second )
                    return std::move(n);
                else
                    return std::nullopt;
            },
            [](std::any i_) -> const void* { // deref
                auto i = std::any_cast<iterator_pair<K, V>>(i_);
                return &*i.first;
            });
    }

}; // namespace type_info

class MapIterator : public detail::DereferencableType {
public:
    using detail::DereferencableType::DereferencableType;

    template<typename T>
    static auto accessor() {
        return [](const Value& v) -> const void* {
            return &*static_cast<const hilti::rt::map::Iterator<typename std::tuple_element<0, T>::type,
                                                                typename std::tuple_element<1, T>::type>*>(v.pointer());
        };
    }
};

class Network : public detail::AtomicType<hilti::rt::Network> {};

class Optional : public detail::DereferencableType {
public:
    using detail::DereferencableType::DereferencableType;

    template<typename T>
    static auto accessor() {
        return [](const Value& v) -> const void* {
            auto x = static_cast<const std::optional<T>*>(v.pointer());
            return x->has_value() ? &*x : nullptr;
        };
    }
};

class Port : public detail::AtomicType<hilti::rt::Port> {};

class Real : public detail::AtomicType<double> {};

class RegExp : public detail::AtomicType<hilti::rt::RegExp> {};

class Result : public detail::DereferencableType {
public:
    using detail::DereferencableType::DereferencableType;

    template<typename T>
    static auto accessor() {
        return [](const Value& v) -> const void* {
            auto x = static_cast<const hilti::rt::Result<T>*>(v.pointer());
            return x->hasValue() ? &*x : nullptr;
        };
    }
    // TODO: Cannot get to the error currently.
};

class Set : public detail::IterableType {
public:
    using detail::IterableType::IterableType;

    template<typename T>
    using iterator_pair =
        std::pair<typename hilti::rt::Set<T>::const_iterator, typename hilti::rt::Set<T>::const_iterator>;

    template<typename T>
    static Accessor accessor() {
        return std::make_tuple(
            [](const Value& v_) -> std::optional<std::any> {
                auto v = static_cast<const hilti::rt::Set<T>*>(v_.pointer());
                if ( v->begin() != v->end() )
                    return make_pair(v->begin(), v->end());
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
};

class SetIterator : public detail::DereferencableType {
public:
    using detail::DereferencableType::DereferencableType;

    template<typename T>
    static auto accessor() {
        return [](const Value& v) -> const void* {
            return &*static_cast<const hilti::rt::set::Iterator<T>*>(v.pointer());
        };
    }
};

template<typename Width>
class SignedInteger : public detail::AtomicType<Width> {};

class Stream : public detail::AtomicType<hilti::rt::Stream> {};

class StreamIterator : public detail::AtomicType<hilti::rt::stream::SafeConstIterator> {};

class StreamView : public detail::AtomicType<hilti::rt::stream::View> {};

class String : detail::AtomicType<std::string> {};

class StrongReference : public detail::DereferencableType {
public:
    using detail::DereferencableType::DereferencableType;

    template<typename T>
    static auto accessor() {
        return [](const Value& v) -> const void* {
            return static_cast<const hilti::rt::StrongReference<T>*>(v.pointer())->get();
        };
    }
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

class Time : public detail::AtomicType<hilti::rt::Time> {};

namespace tuple {

struct Element {
    Element(const char* name, const TypeInfo* type, std::ptrdiff_t offset) : name(name), type(type), offset(offset) {}

    std::string name;
    const TypeInfo* type;
    std::ptrdiff_t offset;
};

}; // namespace tuple

class Tuple {
public:
    Tuple(std::vector<tuple::Element> elements) : _elements(std::move(elements)) {}

    const auto& elements() const { return _elements; }

    auto iterate(const Value& v) const {
        std::vector<std::pair<const tuple::Element&, Value>> values;

        for ( const auto& f : _elements )
            values.emplace_back(f, Value(static_cast<const char*>(v.pointer()) + f.offset, f.type));

        return values;
    }

private:
    std::vector<tuple::Element> _elements;
};

namespace union_ {

struct Field {
    Field(const char* name, const TypeInfo* type) : name(name), type(type) {}

    std::string name;
    const TypeInfo* type;
};

}; // namespace union_

class Union {
public:
    using Accessor = std::function<std::size_t(const Value& v)>;

    Union(std::vector<union_::Field> fields, Accessor accessor)
        : _fields(std::move(fields)), _accessor(std::move(accessor)) {}

    const auto& fields() const { return _fields; }

    Value get(const Value& v) const {
        if ( auto idx = _accessor(v); idx > 0 )
            return Value(v.pointer(), _fields[idx].type);
        else
            return Value(nullptr, nullptr);
    }

    template<typename T>
    static auto accessor() {
        return [](const Value& v) -> std::size_t { return static_cast<const T*>(v.pointer())->index(); };
    }

private:
    std::vector<union_::Field> _fields;
    const Accessor _accessor;
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

    template<typename T, typename Allocator>
    using iterator_pair = std::pair<typename hilti::rt::Vector<T, Allocator>::const_iterator,
                                    typename hilti::rt::Vector<T, Allocator>::const_iterator>;

    template<typename T, typename Allocator = std::allocator<T>>
    static Accessor accessor() {
        return std::make_tuple(
            [](const Value& v_) -> std::optional<std::any> {
                auto v = static_cast<const hilti::rt::Vector<T, Allocator>*>(v_.pointer());
                if ( v->begin() != v->end() )
                    return make_pair(v->begin(), v->end());
                else
                    return std::nullopt;
            },
            [](std::any i_) -> std::optional<std::any> {
                auto i = std::any_cast<iterator_pair<T, Allocator>>(i_);
                auto n = std::make_pair(++i.first, i.second);
                if ( n.first != n.second )
                    return std::move(n);
                else
                    return std::nullopt;
            },
            [](std::any i_) -> const void* {
                auto i = std::any_cast<iterator_pair<T, Allocator>>(i_);
                return &*i.first;
            });
    }
};

class VectorIterator : public detail::DereferencableType {
public:
    using detail::DereferencableType::DereferencableType;

    template<typename T, typename Allocator = std::allocator<T>>
    static auto accessor() {
        return [](const Value& v) -> const void* {
            return &*static_cast<const hilti::rt::vector::Iterator<T, Allocator>*>(v.pointer());
        };
    }
};

class Void : public detail::ValueLessType {};

class WeakReference : public detail::DereferencableType {
public:
    using detail::DereferencableType::DereferencableType;

    template<typename T>
    static auto accessor() {
        return [](const Value& v) -> const void* {
            return static_cast<const hilti::rt::WeakReference<T>*>(v.pointer())->get();
        };
    }
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
        type_info::Any,
        type_info::Bool,
        type_info::Bytes,
        type_info::BytesIterator,
        type_info::Enum,
        type_info::Error,
        type_info::Exception,
        type_info::Function,
        type_info::Interval,
        type_info::Library,
        type_info::Map,
        type_info::MapIterator,
        type_info::Network,
        type_info::Optional,
        type_info::Port,
        type_info::Real,
        type_info::RegExp,
        type_info::Result,
        type_info::Set,
        type_info::SetIterator,
        type_info::SignedInteger<int8_t>,
        type_info::SignedInteger<int16_t>,
        type_info::SignedInteger<int32_t>,
        type_info::SignedInteger<int64_t>,
        type_info::Stream,
        type_info::StreamIterator,
        type_info::StreamView,
        type_info::String,
        type_info::StrongReference,
        type_info::Struct,
        type_info::Time,
        type_info::Tuple,
        type_info::Union,
        type_info::UnsignedInteger<uint8_t>,
        type_info::UnsignedInteger<uint16_t>,
        type_info::UnsignedInteger<uint32_t>,
        type_info::UnsignedInteger<uint64_t>,
        type_info::ValueReference,
        type_info::Vector,
        type_info::VectorIterator,
        type_info::Void,
        type_info::WeakReference
        > type;
};
// clang-format on

} // namespace hilti::rt
