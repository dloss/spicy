// Standalone test application that exercises the HILTI-side type-info API.

#include <tuple>

#include <hilti/rt/libhilti.h>

using namespace hilti::rt;

namespace __hlt::Test {
// Prototypes extracted from the output of "hiltic -P type-info.hlt"
struct TestTypes;
struct TestOptionals;

extern auto makeTestTypes()
    -> std::tuple<hilti::rt::StrongReference<__hlt::Test::TestTypes>,
                  hilti::rt::StrongReference<__hlt::Test::TestTypes>, const ::hilti::rt::TypeInfo*>;

extern auto makeTestOptionals()
    -> std::tuple<hilti::rt::StrongReference<__hlt::Test::TestOptionals>, const ::hilti::rt::TypeInfo*>;
} // namespace __hlt::Test

// Global counters for errors. Test will fail if this is non-zero at termination.
static int errors = 0;

// Macro ensuring two arguments are equal.
#define CHECK_EQ(x, y) __check_eq(x, y, hilti::rt::fmt("%s:%d", __FILE__, __LINE__))

// Macro ensuring a condition is true.
#define CHECK(cond) __check_eq(static_cast<bool>(cond), true, hilti::rt::fmt("%s:%d", __FILE__, __LINE__))

// Macro recording a type is having been visited. Must only be called from
// within one of the visitors defined below.
#define SEEN(type) seen.insert(typeid(x).name());

// Backend for CHECK macros.
template<typename T, typename U>
void __check_eq(const T& x, const U& y, std::string loc) {
    if ( x == y )
        return;

    std::cerr << fmt("Failed comparison: %s == %s (%s)", x, y, loc) << std::endl;
    errors++;
}

// Visitor that checks expected values in fully initialized struct of type "TypesInit".
struct VisitorTypesInit {
    std::set<std::string> seen;
    static inline const int ExepectedVisitorsSeen = 41; // all (43) minus void and function

    // Helper for checking content of a struct of type "S". All our instances
    // of "S" have the same values.
    void testStruct(const type_info::Value& v) {
        auto s = type_info::value::auxType<type_info::Struct>(v).iterate(v);
        auto i = s.begin();
        auto fv = i->second;
        CHECK_EQ(i->first.name, "s");
        CHECK(fv);
        CHECK_EQ(type_info::value::auxType<type_info::String>(fv).get(fv), "string");
        fv = (++i)->second;
        CHECK_EQ(i->first.name, "i");
        CHECK_EQ(type_info::value::auxType<type_info::SignedInteger<int64_t>>(fv).get(fv), 42);
        CHECK(++i == s.end());
    }

    void visit(const hilti::rt::type_info::Value& v) {
        std::visit(type_info::overload{
                       [&](const hilti::rt::type_info::Address& x) {
                           SEEN();
                           CHECK_EQ(x.get(v), Address("1.2.3.4"));
                       },
                       [&](const hilti::rt::type_info::Any& x) { SEEN(); },
                       [&](const hilti::rt::type_info::Bool& x) {
                           SEEN();
                           CHECK_EQ(x.get(v), true);
                       },
                       [&](const hilti::rt::type_info::Bytes& x) {
                           SEEN();
                           CHECK_EQ(x.get(v), "bytes"_b);
                       },
                       [&](const hilti::rt::type_info::BytesIterator& x) {
                           SEEN();
                           CHECK_EQ(*x.get(v), 'b');
                       },
                       [&](const hilti::rt::type_info::Enum& x) {
                           SEEN();
                           CHECK_EQ(x.get(v).value, 2);
                           CHECK_EQ(x.get(v).name, "B");
                           CHECK_EQ(x.labels().size(), 4);
                       },
                       [&](const hilti::rt::type_info::Error& x) {
                           SEEN();
                           CHECK_EQ(x.get(v).description(), "error");
                       },
                       [&](const hilti::rt::type_info::Exception& x) {
                           SEEN();
                           CHECK_EQ(x.get(v).description(), "");
                       },
                       [&](const hilti::rt::type_info::Function& x) { SEEN(); },
                       [&](const hilti::rt::type_info::Interval& x) {
                           SEEN();
                           CHECK_EQ(x.get(v), Interval(5, Interval::SecondTag()));
                       },
                       [&](const hilti::rt::type_info::Library& x) { SEEN(); },
                       [&](const hilti::rt::type_info::Map& x) {
                           SEEN();
                           auto s = x.iterate(v);
                           auto i = s.begin();
                           auto [k1, v1] = hilti::rt::type_info::Map::getKeyValue(*i++);
                           CHECK_EQ(type_info::value::auxType<type_info::UnsignedInteger<uint64_t>>(k1).get(k1), 1);
                           CHECK_EQ(type_info::value::auxType<type_info::String>(v1).get(v1), "foo-1");
                           auto [k2, v2] = hilti::rt::type_info::Map::getKeyValue(*i++);
                           CHECK_EQ(type_info::value::auxType<type_info::UnsignedInteger<uint64_t>>(k2).get(k2), 2);
                           CHECK_EQ(type_info::value::auxType<type_info::String>(v2).get(v2), "foo-2");
                           CHECK(++i == s.end());
                       },
                       [&](const hilti::rt::type_info::MapIterator& x) {
                           SEEN();
                           auto [k1, v1] = hilti::rt::type_info::Map::getKeyValue(x.value(v));
                           CHECK_EQ(type_info::value::auxType<type_info::UnsignedInteger<uint64_t>>(k1).get(k1), 1);
                           CHECK_EQ(type_info::value::auxType<type_info::String>(v1).get(v1), "foo-1");
                       },
                       [&](const hilti::rt::type_info::Network& x) {
                           SEEN();
                           CHECK_EQ(x.get(v), Network("1.2.3.4", 16));
                       },
                       [&](const hilti::rt::type_info::Optional& x) {
                           SEEN();
                           auto i = x.value(v);
                           CHECK(i);
                           CHECK_EQ(type_info::value::auxType<type_info::String>(i).get(i), "optional");
                       },
                       [&](const hilti::rt::type_info::Port& x) {
                           SEEN();
                           CHECK_EQ(x.get(v), Port("1234/udp"));
                       },
                       [&](const hilti::rt::type_info::Real& x) {
                           SEEN();
                           CHECK_EQ(x.get(v), 3.14);
                       },
                       [&](const hilti::rt::type_info::RegExp& x) {
                           SEEN();
                           CHECK(x.get(v) == RegExp("foo"));
                       },
                       [&](const hilti::rt::type_info::Result& x) {
                           SEEN();
                           auto i = x.value(v);
                           CHECK(i);
                           CHECK_EQ(type_info::value::auxType<type_info::String>(i).get(i), "result");
                       },
                       [&](const hilti::rt::type_info::Set& x) {
                           SEEN();
                           auto s = x.iterate(v);
                           auto i = s.begin();
                           CHECK_EQ(type_info::value::auxType<type_info::String>(*i).get(*i), "aaa");
                           ++i;
                           CHECK_EQ(type_info::value::auxType<type_info::String>(*i).get(*i), "bbb");
                           ++i;
                           CHECK_EQ(type_info::value::auxType<type_info::String>(*i).get(*i), "ccc");
                           ++i;
                           CHECK(i == s.end());
                       },
                       [&](const hilti::rt::type_info::SetIterator& x) {
                           SEEN();
                           auto i = x.value(v);
                           CHECK_EQ(type_info::value::auxType<type_info::String>(i).get(i), "aaa");
                       },
                       [&](const hilti::rt::type_info::SignedInteger<int8_t>& x) {
                           SEEN();
                           CHECK_EQ(x.get(v), -8);
                       },
                       [&](const hilti::rt::type_info::SignedInteger<int16_t>& x) {
                           SEEN();
                           CHECK_EQ(x.get(v), -16);
                       },
                       [&](const hilti::rt::type_info::SignedInteger<int32_t>& x) {
                           SEEN();
                           CHECK_EQ(x.get(v), -32);
                       },
                       [&](const hilti::rt::type_info::SignedInteger<int64_t>& x) {
                           SEEN();
                           CHECK_EQ(x.get(v), -64);
                       },
                       [&](const hilti::rt::type_info::Stream& x) {
                           SEEN();
                           CHECK_EQ(x.get(v), Stream("stream"));
                       },
                       [&](const hilti::rt::type_info::StreamIterator& x) {
                           SEEN();
                           CHECK_EQ(*x.get(v), 's');
                       },
                       [&](const hilti::rt::type_info::StreamView& x) {
                           SEEN();
                           CHECK_EQ(x.get(v), Stream("stream"));
                       },
                       [&](const hilti::rt::type_info::String& x) {
                           SEEN();
                           CHECK_EQ(x.get(v), "string");
                       },
                       [&](const hilti::rt::type_info::StrongReference& x) {
                           SEEN();
                           CHECK(x.value(v));
                           testStruct(x.value(v)); // TODO: failure
                       },
                       [&](const hilti::rt::type_info::Struct& x) {
                           SEEN();
                           testStruct(v);
                       },
                       [&](const hilti::rt::type_info::Time& x) {
                           SEEN();
                           CHECK_EQ(x.get(v), Time(1295415110.5, Time::SecondTag()));
                       },
                       [&](const hilti::rt::type_info::Tuple& x) {
                           SEEN();
                           auto s = x.iterate(v);
                           auto i = s.begin();
                           CHECK_EQ(type_info::value::auxType<type_info::SignedInteger<int32_t>>(i->second).get(
                                        i->second),
                                    123);
                           CHECK_EQ(i->first.name, "a");
                           ++i;
                           CHECK_EQ(type_info::value::auxType<type_info::String>(i->second).get(i->second), "string");
                           CHECK_EQ(i->first.name, "");
                           ++i;
                           CHECK_EQ(type_info::value::auxType<type_info::Bool>(i->second).get(i->second), true);
                           CHECK_EQ(i->first.name, "c");
                           ++i;
                           CHECK(i == s.end());
                           CHECK_EQ(x.elements().size(), 3);
                       },
                       [&](const hilti::rt::type_info::Union& x) {
                           SEEN();
                           auto i = x.value(v);
                           CHECK_EQ(type_info::value::auxType<type_info::SignedInteger<int64_t>>(i).get(i), 42);
                           CHECK_EQ(x.fields().size(), 2);
                       },
                       [&](const hilti::rt::type_info::UnsignedInteger<uint8_t>& x) {
                           SEEN();
                           CHECK_EQ(x.get(v), 8);
                       },
                       [&](const hilti::rt::type_info::UnsignedInteger<uint16_t>& x) {
                           SEEN();
                           CHECK_EQ(x.get(v), 16);
                       },
                       [&](const hilti::rt::type_info::UnsignedInteger<uint32_t>& x) {
                           SEEN();
                           CHECK_EQ(x.get(v), 32);
                       },
                       [&](const hilti::rt::type_info::UnsignedInteger<uint64_t>& x) {
                           SEEN();
                           CHECK_EQ(x.get(v), 64);
                       },
                       [&](const hilti::rt::type_info::ValueReference& x) {
                           SEEN();
                           CHECK(x.value(v));
                           testStruct(x.value(v));
                       },
                       [&](const hilti::rt::type_info::Vector& x) {
                           SEEN();
                           SEEN();
                           auto s = x.iterate(v);
                           auto i = s.begin();
                           CHECK_EQ(type_info::value::auxType<type_info::String>(*i).get(*i), "11");
                           ++i;
                           CHECK_EQ(type_info::value::auxType<type_info::String>(*i).get(*i), "22");
                           ++i;
                           CHECK_EQ(type_info::value::auxType<type_info::String>(*i).get(*i), "33");
                           ++i;
                           CHECK(i == s.end());
                       },
                       [&](const hilti::rt::type_info::VectorIterator& x) {
                           SEEN();
                           auto i = x.value(v);
                           CHECK_EQ(type_info::value::auxType<type_info::String>(i).get(i), "11");
                       },
                       [&](const hilti::rt::type_info::Void& x) { SEEN(); },
                       [&](const hilti::rt::type_info::WeakReference& x) {
                           SEEN();
                           CHECK(x.value(v));
                           testStruct(x.value(v)); // TODO: failure
                       },
                       [&](const auto& x) {}},
                   v.type().aux_type_info);
    }
};

// Visitor that checks expected values in default initialized struct of type "TypesInit".
struct VisitorTypesDefault {
    std::set<std::string> seen;
    static inline const int ExepectedVisitorsSeen = 5;

    void visit(const hilti::rt::type_info::Value& v) {
        std::visit(type_info::overload{[&](const hilti::rt::type_info::Optional& x) {
                                           SEEN();
                                           CHECK(! x.value(v));
                                       },
                                       [&](const hilti::rt::type_info::Result& x) {
                                           SEEN();
                                           CHECK(! x.value(v));
                                       },
                                       [&](const hilti::rt::type_info::StrongReference& x) {
                                           SEEN();
                                           CHECK(! x.value(v));
                                       },
                                       [&](const hilti::rt::type_info::Union& x) {
                                           SEEN();
                                           CHECK(! x.value(v));
                                       },
                                       [&](const hilti::rt::type_info::WeakReference& x) {
                                           SEEN();
                                           CHECK(! x.value(v));
                                       },
                                       [&](const auto& x) {}},
                   v.type().aux_type_info);
    }
};

// Visitor that checks expected values in partially initialized struct of type "TypesOptionals".
struct VisitorOptionals {
    int num_strings = 0;
    void visit(const hilti::rt::type_info::Value& v) {
        std::visit(type_info::overload{[&](const hilti::rt::type_info::String& x) {
                                           num_strings++;
                                           CHECK_EQ(x.get(v), "yes");
                                       },
                                       [&](const auto&) {}},
                   v.type().aux_type_info);
    };
};


int main(int argc, char** argv) {
    hilti::rt::init();

    // Call HILTI code to create & initialize struct instances.
    auto [x_init, x_default, ti_types] = __hlt::Test::makeTestTypes();
    auto [x_optionals, ti_optionals] = __hlt::Test::makeTestOptionals();

    // Test instance of TestTypes that has been initialized with known values.
    CHECK(ti_types->id);
    CHECK_EQ(*ti_types->id, "Test::TestTypes");
    CHECK_EQ(ti_types->display, "Test::TestTypes");

    VisitorTypesInit visitor_init;
    auto v_init = type_info::Value(x_init.get(), ti_types);
    for ( auto f : type_info::value::auxType<type_info::Struct>(v_init).iterate(v_init) )
        visitor_init.visit(f.second);

    CHECK_EQ(visitor_init.seen.size(), VisitorTypesInit::ExepectedVisitorsSeen);

    // Test instance of TestTypes that has been initialized with default values.
    VisitorTypesDefault visitor_default;
    auto v_default = type_info::Value(x_default.get(), ti_types);
    for ( auto f : type_info::value::auxType<type_info::Struct>(v_default).iterate(v_default) )
        visitor_default.visit(f.second);

    CHECK_EQ(visitor_default.seen.size(), VisitorTypesDefault::ExepectedVisitorsSeen);

    // Test instances of TestOptions in which one optional has been set.
    VisitorOptionals visitor2;
    auto v_optionals = type_info::Value(x_optionals.get(), ti_optionals);
    int idx = 0;
    for ( auto f : type_info::value::auxType<type_info::Struct>(v_optionals).iterate(v_optionals) ) {
        if ( idx == 0 ) {
            CHECK(f.second);
            visitor2.visit(f.second);
        }

        if ( idx == 1 )
            CHECK(! f.second);

        ++idx;
    }

    CHECK_EQ(visitor2.num_strings, 1);

    // Done testing.

    if ( errors > 0 ) {
        std::cerr << fmt("type-info test failed, %d errors\n", errors);
        exit(1);
    }

    hilti::rt::done();
}
