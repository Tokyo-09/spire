#include <sys/mman.h>
#include <string.h>
#include <unistd.h>

int main() {
    void* mem = mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    memset(mem, 0x90, 4096);
    ((void(*)())mem)();
    return 0;
}
