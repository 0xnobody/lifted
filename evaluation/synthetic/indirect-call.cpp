
using fn = int(*)(int);

int test(fn f, int x)
{
    return f(x) * 2;
}