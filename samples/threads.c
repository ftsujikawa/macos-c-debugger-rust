#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

#define NUM_THREADS 3
#define NUM_ITERS 200

static volatile long counter = 0;

void worker_step(long id) {
    counter++;
    printf("thread %ld: counter=%ld\n", id, counter);
}

void *worker(void *arg) {
    long id = (long)arg;
    /* スレッドごとに開始タイミングをずらし、同一命令への同時ヒットを避ける */
    usleep((useconds_t)(id * 150000));
    for (int i = 0; i < NUM_ITERS; i++) {
        worker_step(id);
        usleep(300000);
    }
    return NULL;
}

int main(void) {
    pthread_t threads[NUM_THREADS];
    for (long i = 0; i < NUM_THREADS; i++) {
        pthread_create(&threads[i], NULL, worker, (void *)i);
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    return 0;
}
