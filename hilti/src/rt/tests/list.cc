// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <functional>
#include <vector>

#include <hilti/rt/types/integer.h>
#include <hilti/rt/types/list.h>
#include <hilti/rt/types/vector.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("List");

TEST_CASE("equal") {
    CHECK_EQ(List<int>(), list::Empty());
    CHECK_EQ(list::Empty(), List<int>());

    CHECK_NE(List<int>({1}), list::Empty());
    CHECK_NE(list::Empty(), List<int>({1}));

    CHECK_EQ(List<int>(), List<int>());
    CHECK_NE(List<int>({1}), List<int>());
    CHECK_EQ(List<int>({1}), List<int>({1}));
}

TEST_CASE("iterator") {
    SUBCASE("equality") {
        List<int> l1({1, 2, 3});
        List<int> l2({1, 2, 3});

        CHECK_THROWS_WITH_AS(operator==(l1.begin(), l2.begin()), "cannot compare iterators into different lists",
                             const InvalidArgument&);

        CHECK_THROWS_WITH_AS(operator==(l1.cbegin(), l2.cbegin()), "cannot compare iterators into different lists",
                             const InvalidArgument&);

        CHECK_EQ(l1.begin(), l1.begin());
        CHECK_EQ(l1.cbegin(), l1.cbegin());
        CHECK_EQ(l1.cend(), l1.cend());
        CHECK_EQ(l1.end(), l1.end());
        CHECK_NE(l1.cbegin(), l1.cend());
    }

    SUBCASE("deref") {
        {
            auto it = List({1}).begin();
            CHECK_THROWS_WITH_AS(*it, "bound object has expired", const InvalidIterator&);
        }
        {
            auto it = List({1}).cbegin();
            CHECK_THROWS_WITH_AS(*it, "bound object has expired", const InvalidIterator&);
        }

        {
            List<int> l({1, 2, 3});
            auto it = l.begin();

            REQUIRE_EQ(*it, 1);

            l = List<int>({11, 22, 33});
            CHECK_THROWS_WITH_AS(*it, "bound object has expired", const InvalidIterator&);
        }
        {
            List<int> l({1, 2, 3});
            auto it = l.cbegin();

            REQUIRE_EQ(*it, 1);

            l = List<int>({11, 22, 33});
            CHECK_THROWS_WITH_AS(*it, "bound object has expired", const InvalidIterator&);
        }

        {
            List<int> l({1});
            CHECK_THROWS_WITH_AS(*l.end(), "iterator is invalid", const IndexError&);
            CHECK_THROWS_WITH_AS(*l.cend(), "iterator is invalid", const IndexError&);
        }
    }

    SUBCASE("increment") {
        List<int> l({1, 2, 3});

        auto it1 = l.begin();
        auto it2 = ++l.begin();

        REQUIRE_NE(it1, it2);

        CHECK_EQ(++list::Iterator<int>(it1), it2);
        CHECK_NE(it1++, it2);
        CHECK_EQ(it1, it2);

        auto cit = l.cbegin();

        l = List<int>();

        CHECK_THROWS_WITH_AS(++it1, "bound object has expired", const InvalidIterator&);
        CHECK_THROWS_WITH_AS(++cit, "bound object has expired", const InvalidIterator&);
    }

    SUBCASE("increment end") {
        List<int> l;

        CHECK_THROWS_WITH_AS(++l.end(), "cannot advance iterator beyond the end of container", const InvalidArgument&);
        CHECK_THROWS_WITH_AS(++l.cend(), "cannot advance iterator beyond the end of container", const InvalidArgument&);
        CHECK_THROWS_WITH_AS(l.end()++, "cannot advance iterator beyond the end of container", const InvalidArgument&);
        CHECK_THROWS_WITH_AS(l.cend()++, "cannot advance iterator beyond the end of container", const InvalidArgument&);
    }

    SUBCASE("stringification") {
        CHECK_EQ(to_string(List<int>().begin()), "<list iterator>");
        CHECK_EQ(to_string(List<int>().cbegin()), "<const list iterator>");

        CHECK_EQ(fmt("%s", List<int>().begin()), "<list iterator>");
        CHECK_EQ(fmt("%s", List<int>().cbegin()), "<const list iterator>");
    }
}

TEST_CASE("make") {
    const auto fn = std::function<int(int)>([](auto&& x) { return x * 2; });
    const auto pred = std::function<bool(int)>([](auto&& x) { return x % 3 == 0; });

    SUBCASE("w/o predicate") {
        CHECK_EQ(list::make(std::vector<int>(), fn), Vector<int>());
        CHECK_EQ(list::make(std::vector({1, 2, 3}), fn), Vector({2, 4, 6}));
    }

    SUBCASE("w/ predicate") {
        CHECK_EQ(list::make(std::vector<int>(), fn, pred), Vector<int>());
        CHECK_EQ(list::make(std::vector({1, 2, 3}), fn, pred), Vector({6}));
    }
}

TEST_SUITE_END();
