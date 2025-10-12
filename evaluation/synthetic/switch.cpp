
int test(int x)
{
    switch (x) {
        case 1:
            x += 10;
            break;
        case 2:
            x += 20;
            break;
        case 3:
            x += 30;
            break;
        default:
            x += 40;
            break;
    }

    return x;
}