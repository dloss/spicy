// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/rt/type-info.h>
#include <hilti/rt/types/reference.h>

namespace spicy::rt {

/**
 * Type-erased wrapper around parsed unit instances.
 *
 * Initially, this will be unbound, i.e., not refer to any particular
 * instance. `init()` then binds it to an instance, which will let
 * `ParsedUnit` hold a strong reference to it.
 */
class ParsedUnit {
public:
    /** Returns typed access to the contained instance. */
    template<typename T>
    const T& get() const {
        if ( auto p = _unit.as<T>() )
            return *p;
        else
            throw hilti::rt::NullReference("parsed unit not set");
    }

    /**
     * Returns a raw pointer to the contained instance, or null if not
     * initialized.
     */
    const void* pointer() const { return _ptr; }

    /**
     * Returns the type information for the contained instance, or null of
     * not initialized.
     */
    const hilti::rt::TypeInfo* typeinfo() const { return _ti; }

    /** Releases any contained instance. */
    void reset() {
        _unit.reset();
        _ptr = nullptr;
        _ti = nullptr;
    }

    /**
     * Initializes the wrapper with a particular parse unit instance. The
     * `ParsedUnit` will hold a strong reference to the instance until
     * released.
     *
     * @param u type-erased wrapper to initialize
     * @param t reference to instance to initialize `u` with
     * @param ti type information for `T`
     */
    template<typename T>
    static void initialize(ParsedUnit& u, const hilti::rt::ValueReference<T>& t, const hilti::rt::TypeInfo* ti) {
        u._unit = hilti::rt::StrongReference(t);
        u._ptr = t.get();
        u._ti = ti;
    }

private:
    hilti::rt::StrongReferenceGeneric _unit;
    const hilti::rt::TypeInfo* _ti;
    const void* _ptr;
};

} // namespace spicy::rt
