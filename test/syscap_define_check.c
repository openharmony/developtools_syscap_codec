#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "syscap_define.h"

int main()
{
    size_t size = sizeof(g_arraySyscap) / sizeof(SyscapWithNum);
    size_t flag = 0;

    for (size_t i = 0; i < size; i++) {
        if (g_arraySyscap[i].num != i) {
            printf("[Error]: %s -> num(%u) should be %lu.\n", g_arraySyscap[i].str, g_arraySyscap[i].num, i);
            flag++;
        }
    }
    if (flag == 0) {
        return 0;
    } else {
        return -1;
    }
}