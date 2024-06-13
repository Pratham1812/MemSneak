from bcc import BPF
from time import sleep
from datetime import datetime
import resource
import argparse
import subprocess
import os
import sys

description = """
This tool is used to sneak for memory leaks in a process. It traces outstanding memory allocations that were not freed by a process.
It supports both user mode allocations and kernel mode allocations. Currently supporting memory allocation performed with various libc functions and also kernel mode functions like kmalloc/kmem_cache_alloc/get_free_pages.
"""

parser = argparse.ArgumentParser(
    description=description, formatter_class=argparse.RawTextHelpFormatter
)

parser.add_argument(
    "-p",
    "--pid",
    type=int,
    default=-1,
    help="the PID to trace; if not specified, trace kernel allocs",
)
parser.add_argument(
    "-t",
    "--trace",
    action="store_true",
    help="print trace messages for each alloc/free call",
)

parser.add_argument(
    "-a",
    "--show-allocs",
    default=False,
    action="store_true",
    help="show allocation addresses and sizes as well as call stacks",
)

parser.add_argument("-c", "--command", help="execute and trace the specified command")

parser.add_argument(
    "-s",
    "--sample-rate",
    default=1,
    type=int,
    help="sample every N-th allocation to decrease the overhead",
)

parser.add_argument(
    "--sort",
    type=str,
    default="size",
    help="report sorted in given key; available key list: size, count",
)

parser.add_argument(
    "-d", "--delay", type=int, default=1, help="Delay in seconds between each sample"
)

parser.add_argument(
    "-v", "--verbose", action="store_true", default=False, help="display verbose output"
)

args = parser.parse_args()

pid = args.pid
trace_all = args.trace
delay = args.delay
verbose = args.verbose
sample_rate = args.sample_rate
sort_key = args.sort
command = args.command
trace_kernel = pid == -1


def get_pid(command):
    p = subprocess.Popen(command.split())
    return p.pid


sort_keys = ["size", "count"]
alloc_sort_map = {sort_keys[0]: lambda a: a.size, sort_keys[1]: lambda a: a.count}
combined_sort_map = {
    sort_keys[0]: lambda a: -a[1].total_size,
    sort_keys[1]: lambda a: -a[1].number_of_allocs,
}

if sort_key not in sort_keys:
    print("Given sort_key:", sort_key)
    print("Supporting sort key list:", sort_keys)
    exit(1)
if command is not None:
    print("Executing '{}' and tracing the process.".format(command))
    try:
        pid = get_pid(command)
    except Exception as e:
        print("Error while executing the command: ", e)
        exit(1)
if pid == -1:
    print("Either specify a PID or a command to trace")
    exit(1)

with open("bpf_source.c") as bpffile:
    bpf_source = bpffile.read()

bpf_source = bpf_source.replace("SHOULD_PRINT", "1" if verbose else "0")
bpf_source = bpf_source.replace("SAMPLE_EVERY_N", str(sample_rate))

bpf_source = bpf_source.replace("PAGE_SIZE", str(resource.getpagesize()))

stack_flag = "0"
if not trace_kernel:
    stack_flag += "|BPF_F_USER_STACK"
bpf_source = bpf_source.replace("STACK_FLAGS", stack_flag)

bpf = BPF(text=bpf_source)

if trace_kernel:
    print("Tracing kernel memory allocations..........")
else:
    print("Tracing process with PID: ", pid)
    def attach_probes(sym, fn_prefix=None, can_fail=False, need_uretprobe=True):
                if fn_prefix is None:
                        fn_prefix = sym
                try:
                        bpf.attach_uprobe(sym=sym,
                                          fn_name=fn_prefix + "_enter",
                                          pid=pid)
                        if need_uretprobe:
                                bpf.attach_uretprobe(sym=sym,
                                             fn_name=fn_prefix + "_exit",
                                             pid=pid)
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
    attach_probes("munmap", can_fail=True, need_uretprobe=False) # failed on jemalloc
