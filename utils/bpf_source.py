from bcc import BPF
import resource
import os
def generate_bpf_source(args):
    file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../','static', 'bpf_source.c')

    with open(file_path) as bpffile:
        bpf_source = bpffile.read()
    bpf_source = bpf_source.replace("SHOULD_PRINT", "1" if args.verbose else "0")
    bpf_source = bpf_source.replace("SAMPLE_EVERY_N", str(args.sample_rate))

    bpf_source = bpf_source.replace("PAGE_SIZE", str(resource.getpagesize()))

    stack_flag = "0"
    if not args.trace_kernel:
        stack_flag += "|BPF_F_USER_STACK"
    bpf_source = bpf_source.replace("STACK_FLAGS", stack_flag)

    return bpf_source
    

