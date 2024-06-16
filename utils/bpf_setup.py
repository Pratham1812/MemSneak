from bcc import BPF
from utils.bpf_source import generate_bpf_source

def setup_bpf(args):
    bpf_source = generate_bpf_source(args)
    bpf = BPF(text=bpf_source)
    if(not args.trace_kernel):
        def attach_probes(sym, fn_prefix=None, can_fail=False, need_uretprobe=True):
                if fn_prefix is None:
                        fn_prefix = sym
                try:
                        bpf.attach_uprobe(name="c", sym=sym,
                                          fn_name=fn_prefix + "_in",
                                          pid=args.pid)
                        if need_uretprobe:
                                bpf.attach_uretprobe(name="c", sym=sym,
                                             fn_name=fn_prefix + "_out",
                                             pid=args.pid)
                except Exception:
                        if can_fail:
                                return
                        else:
                                raise
        attach_probes("malloc")
        attach_probes("calloc")
        attach_probes("realloc")
        attach_probes("mmap", can_fail=True) # failed on jemalloc
        attach_probes("posix_memalign")
        attach_probes("valloc", can_fail=True) # failed on Android, is deprecated in libc.so from bionic directory
        attach_probes("memalign")
        attach_probes("pvalloc", can_fail=True) # failed on Android, is deprecated in libc.so from bionic directory
        attach_probes("aligned_alloc", can_fail=True)  # added in C11
        attach_probes("free", need_uretprobe=False)
        attach_probes("munmap", can_fail=True, need_uretprobe=False) # failed on jemalloc# failed on jemalloc
    
    return bpf
