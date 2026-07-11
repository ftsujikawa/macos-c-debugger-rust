#include <stdio.h>

int add(int a, int b) {
    return a + b;
}

int main() {
    for (int i = 0; i < 3; i++) {
        printf("hello %d\n", i);
    }
    
    int result = add(2, 3);
    printf("2 + 3 = %d\n", result);
    
    return 0;
}
