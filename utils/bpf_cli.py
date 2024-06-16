import argparse
import subprocess

def get_pid(command):
    p = subprocess.Popen(command.split())
    pid = p.pid
    return pid


def parse_arguments():

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
        "--duration",type=int, default=10000, help="Duration to run the tool"
    )

    parser.add_argument("--combined", default=False, action="store_true",
            help="show combined allocation statistics only")

    parser.add_argument("--freq", default=False, action="store_true",help="show frequency of each function call")

    parser.add_argument(
        "-v", "--verbose", action="store_true", default=False, help="display verbose output"
    )
    args = parser.parse_args()
    sort_keys = ["size", "count"]
    if args.sort not in sort_keys:
        print("Given sort_key:", args.sort_key)
        print("Supporting sort key list:", sort_keys)
        raise ValueError("Invalid sort key")
    if args.command is not None:
        print("Executing '{}' and tracing the process.".format(args.command))
        try:
            args.pid = get_pid(args.command)
        except Exception as e:
            raise ValueError("Failed to execute the command")
            
    args.trace_kernel = (args.pid == -1)
    return args



