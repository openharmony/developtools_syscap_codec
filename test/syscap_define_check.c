#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "syscap_define.h"

int main()
{
    size_t size = sizeof(g_arraySyscap) / sizeof(SyscapWithNum);
    // printf("size = %lu\n", size);
    int flag = 0;

    for (int i = 0; i < size; i++) {
        if (g_arraySyscap[i].num != i) {
            printf("[Error]: %s -> num(%u) should be %d.\n", g_arraySyscap[i].str, g_arraySyscap[i].num, i);
            flag++;
        }
    }
    // if (flag == 0) return 0;
    // else exit(1);
    exit(1);
}