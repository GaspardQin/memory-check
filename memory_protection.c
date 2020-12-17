#include <errno.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h> //memset
#include <stdio.h>
#define SHARED_ARRAY_LEN 32
int *shared_ptr;
size_t shared_data_len; // in byte

// initialize the shared_ptr
void init_memory()
{
    shared_data_len = SHARED_ARRAY_LEN * sizeof(int);
    shared_ptr = (int *)valloc(shared_data_len); // vmalloc(alloc_size) is equal to aligned_alloc(page_size, alloc_size)
    memset(shared_ptr, 0, SHARED_ARRAY_LEN * sizeof(int));
}

void release_memory()
{
    free(shared_ptr);
}

void mem_write()
{
    int i = (int)((float)rand() / (float)RAND_MAX * SHARED_ARRAY_LEN);
    shared_ptr[i] = -100;
    printf("writed %d th number to %d\n", i, -100);
}

void mem_read()
{
    int i = (int)((float)rand() / (float)RAND_MAX * SHARED_ARRAY_LEN);
    printf("read %d th number: %d\n", i, shared_ptr[i]);
}

static void signal_handler(int sig, siginfo_t *si, void *unused)
{
    /* Note: calling printf() from a signal handler is not safe
        (and should not be done in production programs), since
        printf() is not async-signal-safe; see signal-safety(7).
        Nevertheless, we use printf() here as a simple way of
        showing that the handler was called. */

    printf("Illegal access ! Got SIGSEGV at address: %p\n", si->si_addr);


    // this is optional
    mprotect(shared_ptr, shared_data_len, PROT_READ | PROT_WRITE); // set it back to accessible, otherwise the demo will not continue
}

void register_signal()
{
    struct sigaction sa;

    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = signal_handler;
    if (sigaction(SIGSEGV, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
        
}

int main()
{
    int page_size = sysconf(_SC_PAGE_SIZE);
    init_memory();
    register_signal();
    printf("Read and write as normal\n");

    mem_read();
    mem_write();

    printf("Set the memory only readable\n");
    mprotect(shared_ptr, shared_data_len, PROT_READ);

    mem_read();
    mem_write(); // here a signal should be generated

    printf("Set the memory unaccesible\n");
    mprotect(shared_ptr, shared_data_len, PROT_NONE);

    mem_read(); // heare a signal should be generated
    mprotect(shared_ptr, shared_data_len, PROT_NONE);
    mem_write(); // heare a signal should be generated

    printf("Set the memory readable and writeable\n");
    mprotect(shared_ptr, shared_data_len, PROT_READ | PROT_WRITE);
    
    mem_read(); //should be ok
    mem_write(); // shoud be ok
    release_memory();
}
