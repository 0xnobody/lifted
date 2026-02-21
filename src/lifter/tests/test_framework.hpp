#pragma once

// Minimal zero-dependency test framework.
//
// Usage:
//   TEST(my_test_name) { CHECK(1 + 1 == 2); CHECK_EQ(x, y); }
//
// Define tests in any translation unit. Call test::run_all() from main().
// Returns the number of failed test cases.

#include <cmath>
#include <functional>
#include <iostream>
#include <string_view>
#include <vector>

namespace test
{
    struct TestCase
    {
        std::string_view name;
        std::function<void()> fn;
    };

    inline std::vector<TestCase> &registry()
    {
        static std::vector<TestCase> g;
        return g;
    }

    inline int &failure_count()
    {
        static int n = 0;
        return n;
    }

    inline int &assertion_count()
    {
        static int n = 0;
        return n;
    }

    inline void register_test(std::string_view name, std::function<void()> fn)
    {
        registry().push_back({name, fn});
    }

    inline void check(bool cond, std::string_view expr, std::string_view file, int line)
    {
        ++assertion_count();
        if (!cond)
        {
            ++failure_count();
            std::cerr << "    FAIL: " << expr << "  (" << file << ":" << line << ")\n";
        }
    }

    inline int run_all()
    {
        int case_failures = 0;
        for (auto &tc : registry())
        {
            int prev = failure_count();
            std::cout << "[ RUN  ] " << tc.name << "\n";
            tc.fn();
            if (failure_count() == prev)
                std::cout << "[ PASS ] " << tc.name << "\n";
            else
            {
                std::cout << "[ FAIL ] " << tc.name << "\n";
                ++case_failures;
            }
        }
        int total = static_cast<int>(registry().size());
        int passed = total - case_failures;
        std::cout << "\n"
                  << passed << "/" << total << " tests passed, "
                  << assertion_count() << " assertions, "
                  << failure_count() << " assertion failures\n";
        return case_failures;
    }
} // namespace test

// ── Assertion macros ──────────────────────────────────────────────────────

#define CHECK(expr) \
    ::test::check(static_cast<bool>(expr), #expr, __FILE__, __LINE__)

#define CHECK_EQ(a, b) \
    ::test::check((a) == (b), #a " == " #b, __FILE__, __LINE__)

#define CHECK_NE(a, b) \
    ::test::check((a) != (b), #a " != " #b, __FILE__, __LINE__)

#define CHECK_LT(a, b) \
    ::test::check((a) < (b), #a " < " #b, __FILE__, __LINE__)

#define CHECK_GT(a, b) \
    ::test::check((a) > (b), #a " > " #b, __FILE__, __LINE__)

// ── Test registration macro ───────────────────────────────────────────────

#define TEST(name)                                                               \
    static void test_fn_##name();                                                \
    static struct TestRegistrar_##name                                           \
    {                                                                            \
        TestRegistrar_##name() { ::test::register_test(#name, test_fn_##name); } \
    } test_reg_##name;                                                           \
    static void test_fn_##name()
