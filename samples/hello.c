#include <stdio.h>
#include <stdlib.h>

int add(int a, int b) {
    return a + b;
}

int main() {
    for (int i = 0; i < 3; i++) {
        printf("hello %d\n", i);
    }
    
    int result = add(2, 3);
    printf("2 + 3 = %d\n", result);
    
    for (int i = 0; i < 10; i++) {
        void *p = malloc(1024);
        free(p);
    }

    int i = 0;
    while(1) {
        printf("result = %d\n", i++);
    }

    return 0;
}
