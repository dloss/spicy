
#include <hilti/rt/libhilti.h>

namespace __hlt::Test {
struct X;
extern auto makeX() -> std::tuple<hilti::rt::StrongReference<__hlt::Test::X>, const ::hilti::rt::TypeInfo*>;
extern auto makeDefaultX() -> std::tuple<hilti::rt::StrongReference<__hlt::Test::X>, const ::hilti::rt::TypeInfo*>;
}

int main(int argc, char** argv) {
    hilti::rt::init();

    auto x = __hlt::Test::makeX();
    hilti::rt::type_info::Value v = {std::get<0>(x).get(), std::get<1>(x) };
    std::cerr << v.type().display << std::endl;

    x = __hlt::Test::makeDefaultX();
    v = {std::get<0>(x).get(), std::get<1>(x) };
    std::cerr << v.type().display << std::endl;

    hilti::rt::done();
}
