// A small multi-threaded program whose threads block for different
// reasons, to see how they look to the offcpu module:
//
//   pool-worker x4  - idle, waiting on a condition variable for jobs
//   dispatcher      - hands out one job every 200ms, sleeping in between
//   contender x3    - fight over one mutex, each holding it for 2ms
//   log-writer      - writes 64KB and fdatasync()s it, in a loop
//
// The functions offcpu should show in user stacks are noinline, so they
// keep their own frames even at -O2.

#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define POOL_WORKERS 4
#define CONTENDERS 3
#define JOB_INTERVAL_US 200000
#define JOB_US 1000
#define CRITICAL_SECTION_US 2000
#define OUTSIDE_LOCK_US 500
#define LOG_CHUNK (64 * 1024)
#define LOG_SIZE (16 * 1024 * 1024)

static const char *log_path = "/var/log/blocking-mix.log";

// Burns CPU, rather than sleeping, for us microseconds.
static void spin(long us)
{
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    do {
        clock_gettime(CLOCK_MONOTONIC, &now);
    } while ((now.tv_sec - start.tv_sec) * 1000000L + (now.tv_nsec - start.tv_nsec) / 1000 < us);
}

// --- thread pool: workers idle until the dispatcher queues a job ---

static pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;
static int queue_len;

__attribute__((noinline)) static void wait_for_job(void)
{
    pthread_mutex_lock(&queue_lock);
    while (queue_len == 0) {
        pthread_cond_wait(&queue_cond, &queue_lock);
    }
    queue_len--;
    pthread_mutex_unlock(&queue_lock);
}

static void *pool_worker(void *arg)
{
    for (;;) {
        wait_for_job();
        spin(JOB_US);
    }
    return NULL;
}

__attribute__((noinline)) static void wait_for_next_tick(void)
{
    usleep(JOB_INTERVAL_US);
}

static void *dispatcher(void *arg)
{
    for (;;) {
        wait_for_next_tick();
        pthread_mutex_lock(&queue_lock);
        queue_len++;
        pthread_cond_signal(&queue_cond);
        pthread_mutex_unlock(&queue_lock);
    }
    return NULL;
}

// --- lock contention: the lock is held almost all the time ---

static pthread_mutex_t state_lock = PTHREAD_MUTEX_INITIALIZER;

__attribute__((noinline)) static void update_shared_state(void)
{
    pthread_mutex_lock(&state_lock);
    spin(CRITICAL_SECTION_US);
    pthread_mutex_unlock(&state_lock);
}

static void *contender(void *arg)
{
    for (;;) {
        update_shared_state();
        spin(OUTSIDE_LOCK_US);
    }
    return NULL;
}

// --- disk I/O: every write is flushed before the next one ---

__attribute__((noinline)) static void flush_log(int fd)
{
    if (fdatasync(fd) != 0) {
        perror("fdatasync");
        exit(1);
    }
}

__attribute__((noinline)) static void append_log(int fd, const char *buf, off_t off)
{
    if (pwrite(fd, buf, LOG_CHUNK, off) != LOG_CHUNK) {
        perror("pwrite");
        exit(1);
    }
}

static void *log_writer(void *arg)
{
    int fd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open");
        exit(1);
    }
    static char buf[LOG_CHUNK];
    memset(buf, 'x', sizeof(buf));
    // Cycles over a fixed-size region so the file doesn't grow forever.
    for (off_t off = 0;; off = (off + LOG_CHUNK) % LOG_SIZE) {
        append_log(fd, buf, off);
        flush_log(fd);
    }
    return NULL;
}

static void start(const char *name, void *(*fn)(void *))
{
    pthread_t t;
    if (pthread_create(&t, NULL, fn, NULL) != 0) {
        perror("pthread_create");
        exit(1);
    }
    // Thread names become comm, so offcpu can tell the threads apart even
    // before looking at stacks. 15 characters max.
    pthread_setname_np(t, name);
}

int main(void)
{
    printf("Starting blocking-mix. PID=%d\n", getpid());
    fflush(stdout);

    for (int i = 0; i < POOL_WORKERS; i++) {
        start("pool-worker", pool_worker);
    }
    start("dispatcher", dispatcher);
    for (int i = 0; i < CONTENDERS; i++) {
        start("contender", contender);
    }
    start("log-writer", log_writer);

    for (;;) {
        pause();
    }
}
