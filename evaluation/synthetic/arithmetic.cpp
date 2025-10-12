
__declspec(dllexport) extern "C" int test(int x) 
{
    return (x * 2) | 7772 & x + 442;
}