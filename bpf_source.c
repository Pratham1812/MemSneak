#include <uapi/linux/ptrace.h>

struct alloc_info {
        u64 size;
        u64 timestamp_ns;
        int stack_id;
};

struct combined_alloc_info {
        u64 total_size;
        u64 total_number_of_allocs;
};

#define KERNEL 0
#define MALLOC 1
#define CALLOC 2
#define REALLOC 3
#define MMAP 4
#define POSIX_MEMALIGN 5
#define VALLOC 6
#define MEMALIGN 7
#define PVALLOC 8
#define ALIGNED_ALLOC 9
#define FREE 10
#define MUNMAP 11

BPF_HASH(sizes, u64, u64);
BPF_HASH(allocs, u64, struct alloc_info, 1000000);
BPF_HASH(memptrs, u32, u64);
BPF_STACK_TRACE(stack_traces, 10240);
BPF_HASH(combined_allocs, u64, struct combined_alloc_info, 10240);

static inline void update_statistics_add(u64 stack_id, u64 sz) {
        struct combined_alloc_info *existing_allocs;
        struct combined_alloc_info cinfo = {0, 0};

        existing_allocs = combined_allocs.lookup(&stack_id);
        if (!existing_allocs) {
                combined_allocs.update(&stack_id, &cinfo);
                existing_allocs = combined_allocs.lookup(&stack_id);
                if (!existing_allocs)
                        return;
        }
        __sync_fetch_and_add(&existing_allocs->total_size, sz);
        __sync_fetch_and_add(&existing_allocs->total_number_of_allocs, 1);
}

static inline void update_statistics_del(u64 stack_id, u64 sz) {
        struct combined_alloc_info *existing_allocs;

        existing_allocs = combined_allocs.lookup(&stack_id);
        if (!existing_allocs)
                return;

        if (existing_allocs->total_number_of_allocs > 1) {
                __sync_fetch_and_sub(&existing_allocs->total_size, sz);
                __sync_fetch_and_sub(&existing_allocs->total_number_of_allocs, 1);
        } else {
                combined_allocs.delete(&stack_id);
        }
}

static inline int gen_alloc_enter(struct pt_regs *ctx, size_t size, u32 type_index) {
        if (SAMPLE_EVERY_N > 1) {
                u64 ts = bpf_ktime_get_ns();
                if (ts % SAMPLE_EVERY_N != 0)
                        return 0;
        }

        u32 tid = bpf_get_current_pid_tgid();
        u64 size64 = size;
        u64 key = (uint64_t)type_index << 32 | tid;
        sizes.update(&key, &size64);

        if (SHOULD_PRINT)
                bpf_trace_printk("alloc entered, size = %u\\n", size);
        return 0;
}

static inline int gen_alloc_exit(struct pt_regs *ctx, u64 address, u32 type_index) {
        u32 tid = bpf_get_current_pid_tgid();
        u64 key = (uint64_t)type_index << 32 | tid;
        u64* size64 = sizes.lookup(&key);
        struct alloc_info info = {0};

        if (size64 == 0)
                return 0; // missed alloc entry

        info.size = *size64;
        sizes.delete(&key);

        if (address != 0) {
                info.timestamp_ns = bpf_ktime_get_ns();
                info.stack_id = stack_traces.get_stackid(ctx, STACK_FLAGS);
                allocs.update(&address, &info);
                update_statistics_add(info.stack_id, info.size);
        }

        if (SHOULD_PRINT) {
                bpf_trace_printk("alloc exited, size = %lu, result = %lx\\n",
                                 info.size, address);
        }
        return 0;
}



static inline int gen_free_enter(struct pt_regs *ctx, void *address) {
        u64 addr = (u64)address;
        struct alloc_info *info = allocs.lookup(&addr);
        if (info == 0)
                return 0;

        allocs.delete(&addr);
        update_statistics_del(info->stack_id, info->size);

        if (SHOULD_PRINT) {
                bpf_trace_printk("free entered, address = %lx, size = %lu\\n",
                                 address, info->size);
        }
        return 0;
}

int malloc_enter(struct pt_regs *ctx, size_t size) {
        return gen_alloc_enter(ctx, size, MALLOC);
}

int malloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx, PT_REGS_RC(ctx), MALLOC);
}

int free_enter(struct pt_regs *ctx, void *address) {
        return gen_free_enter(ctx, address);
}

int calloc_enter(struct pt_regs *ctx, size_t nmemb, size_t size) {
        return gen_alloc_enter(ctx, nmemb * size, CALLOC);
}

int calloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx,PT_REGS_RC(ctx),CALLOC);
}

int realloc_enter(struct pt_regs *ctx, void *ptr, size_t size) {
        gen_free_enter(ctx, ptr);
        return gen_alloc_enter(ctx, size, REALLOC);
}

int realloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx,PT_REGS_RC(ctx),REALLOC);
}

int mmap_enter(struct pt_regs *ctx) {
        size_t size = (size_t)PT_REGS_PARM2(ctx);
        return gen_alloc_enter(ctx, size, MMAP);
}

int mmap_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx,PT_REGS_RC(ctx),MMAP);
}

int munmap_enter(struct pt_regs *ctx, void *address) {
        return gen_free_enter(ctx, address);
}

int posix_memalign_enter(struct pt_regs *ctx, void **memptr, size_t alignment,
                         size_t size) {
        u64 memptr64 = (u64)(size_t)memptr;
        u32 tid = bpf_get_current_pid_tgid();

        memptrs.update(&tid, &memptr64);
        return gen_alloc_enter(ctx, size, POSIX_MEMALIGN);
}

int posix_memalign_exit(struct pt_regs *ctx) {
        u32 tid = bpf_get_current_pid_tgid();
        u64 *memptr64 = memptrs.lookup(&tid);
        void *addr;

        if (memptr64 == 0)
                return 0;

        memptrs.delete(&tid);

        if (bpf_probe_read_user(&addr, sizeof(void*), (void*)(size_t)*memptr64))
                return 0;

        u64 addr64 = (u64)(size_t)addr;
        return gen_alloc_exit(ctx, addr64, POSIX_MEMALIGN);
}

int aligned_alloc_enter(struct pt_regs *ctx, size_t alignment, size_t size) {
        return gen_alloc_enter(ctx, size, ALIGNED_ALLOC);
}

int aligned_alloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx,PT_REGS_RC(ctx),ALIGNED_ALLOC);
}

int valloc_enter(struct pt_regs *ctx, size_t size) {
        return gen_alloc_enter(ctx, size, VALLOC);
}

int valloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx,PT_REGS_RC(ctx),VALLOC);
}

int memalign_enter(struct pt_regs *ctx, size_t alignment, size_t size) {
        return gen_alloc_enter(ctx, size, MEMALIGN);
}

int memalign_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx,PT_REGS_RC(ctx),MEMALIGN);
}

int pvalloc_enter(struct pt_regs *ctx, size_t size) {
        return gen_alloc_enter(ctx, size, PVALLOC);
}

int pvalloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx,PT_REGS_RC(ctx),PVALLOC);
}


TRACEPOINT_PROBE(kmem, kmalloc) {
        gen_alloc_enter((struct pt_regs *)args, args->bytes_alloc, KERNEL);
        return gen_alloc_exit((struct pt_regs *)args, (size_t)args->ptr, KERNEL);
}

TRACEPOINT_PROBE(kmem, kfree) {
        return gen_free_enter((struct pt_regs *)args, (void *)args->ptr);
}

TRACEPOINT_PROBE(kmem, kmem_cache_alloc) {
        gen_alloc_enter((struct pt_regs *)args, args->bytes_alloc, KERNEL);
        return gen_alloc_exit((struct pt_regs *)args, (size_t)args->ptr, KERNEL);
}

TRACEPOINT_PROBE(kmem, kmem_cache_free) {
        return gen_free_enter((struct pt_regs *)args, (void *)args->ptr);
}

TRACEPOINT_PROBE(kmem, mm_page_alloc) {
        gen_alloc_enter((struct pt_regs *)args, PAGE_SIZE << args->order, KERNEL);
        return gen_alloc_exit((struct pt_regs *)args, args->pfn, KERNEL);
}

TRACEPOINT_PROBE(kmem, mm_page_free) {
        return gen_free_enter((struct pt_regs *)args, (void *)args->pfn);
}
