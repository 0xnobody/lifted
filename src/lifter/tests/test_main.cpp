#include "test_framework.hpp"
#include <cstdlib>

int main()
{
    return test::run_all() == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
