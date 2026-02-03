
#include "types.hpp"
#include "verification.hpp"

extern "C" Memory *__src_fn(addr_t address,
                            Memory *__restrict__ memory,
                            rptr8 rcx,
                            rptr8 rdx,
                            rptr8 rsp,
                            rptr8 rsi,
                            rptr8 rdi,
                            rptr8 rax);

extern "C" Memory *__tgt_fn(addr_t address,
                            Memory *__restrict__ memory,
                            rptr8 rcx,
                            rptr8 rdx,
                            rptr8 rsp,
                            rptr8 rsi,
                            rptr8 rdi,
                            rptr8 rax);

/*
extern "C" bool __verify(uint64_t seed)
{
std::mt19937_64 rng(seed);
std::uniform_int_distribution<uint64_t> dist(0, 0xFFFFFFFFFFFFFFFF);

uint64_t rcx = dist(rng);
uint64_t rdx = dist(rng);
uint64_t rsi = dist(rng);
uint64_t rdi = dist(rng);
uint64_t rsp = 0xFFFFFFFF00000000;
uint64_t rax = 0;

Memory src_mem_state(rand_memory_state{&rng});

__src_fn(0, &src_mem_state, &rcx, &rdx, &rsp, &rsi, &rdi, &rax);

fprintf(stdout, "Source memory state:\n");
src_mem_state.m.debug_memory_state();

Memory tgt_mem_state(rand_memory_state{src_mem_state.m.get_initial_state()});

__tgt_fn(0, &tgt_mem_state, &rcx, &rdx, &rsp, &rsi, &rdi, &rax);

fprintf(stdout, "Target memory state:\n");
tgt_mem_state.m.debug_memory_state();

fprintf(stdout, "Comparing memory states:\n");
src_mem_state.m.debug_compare_memory_state(tgt_mem_state.m);

return src_mem_state.m == tgt_mem_state.m;
}

extern "C" bool __verify_n(int N)
{
std::random_device dev;
for (int i = 0; i < N; i++)
{
uint64_t seed = dev();
if (!__verify(seed))
{
printf("[!] verification failed with seed %lx\n", seed);
}
return false;
}
return true;
}
*/
int main(int argc, char **argv)
{
    // std::random_device dev;
    // uint64_t seed = dev();
    // bool success = __verify(seed);
    // printf("Verification %s\n", success ? "succeeded" : "failed");
}