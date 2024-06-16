from datetime import datetime
from prettytable import PrettyTable
top_stacks = 10 #change this to get more stacks
stack_depth = 5 #change this to get more stack depth
count_func = {};
def print_outstanding(bpf,pid,sort_key):
        
        sort_keys = ["size", "count"]
        alloc_sort_map = {sort_keys[0]: lambda a: a[1].size, sort_keys[1]: lambda a: a[1].count}
        print("[%s] Top %d stacks with outstanding allocations:" %
              (datetime.now().strftime("%H:%M:%S"), top_stacks))
        allocs = sorted(bpf["allocs"].items(),key=alloc_sort_map[sort_key])
        stack_traces = bpf["stack_traces"]
        no_of_entries = top_stacks;
        entries = PrettyTable(['Address', 'Size(KB)','stackID','stackData'])
        for address,info in allocs:
            try:
                stack_data = PrettyTable(['Stack'])
                count = 0;
                for addr in stack_traces.walk(info.stack_id):
                    sym = bpf.sym(addr,pid,show_module=True,show_offset=True)
                    add = ('0x'+format(addr,'016x')+'\t').encode('utf-8')
                    stack_data.add_row([sym.decode('utf-8')])
                    count+=1;
                    if count == stack_depth:
                        break
                entries.add_row([('0x'+format(address.value,'016x')).encode('utf-8'),info.size//1024,('0x'+format(info.stack_id,'016x')).encode('utf-8'),stack_data])
            except KeyError:
                stack_data = PrettyTable(['Stack'])
                stack_data.add_row(["[unknown]"])
                entries.add_row([('0x'+format(address.value,'016x')).encode('utf-8'),info.size//1024,"stack id lost","[unknown]"])
            print(entries)
            no_of_entries-=1;
            if(no_of_entries<0):break

def print_outstanding_combined(bpf,pid,sort_key):
        sort_keys = ["size", "count"]
        combined_sort_map = {
            sort_keys[0]: lambda a: -a[1].total_size,
            sort_keys[1]: lambda a: -a[1].total_number_of_allocs,
        }
        stack_traces = bpf["stack_traces"]
        stacks = sorted(bpf["combined_allocs"].items(),
                        key=combined_sort_map[sort_key])
        cnt = 1
        entries = PrettyTable(['Size (KB)', 'No. of Allocations','stackID','stackData'])
        entries.padding_width=2
        
        for stack_id,info in stacks:
                stack_data = PrettyTable(['Stack'],)
                top_stack = 0
                try:
                    for addr in stack_traces.walk(stack_id.value):
                        sym = bpf.sym(addr,pid,show_module=True,show_offset=True)
                        add = ('0x'+format(addr,'016x')+'\t').encode('utf-8')
                        stack_data.add_row([sym.decode('utf-8')])
                        top_stack+=1
                        if top_stack == 5:
                            break
                except KeyError:
                    stack_data.add_row(["stack information lost"])    
                
                entries.add_row([info.total_size//1024, info.total_number_of_allocs,('0x'+format(stack_id.value,'016x')).encode('utf-8'),stack_data])
                cnt+=1;
                if cnt == top_stack:
                    break

        print("[%s] Top %d stacks with outstanding allocations:" %
              (datetime.now().strftime("%H:%M:%S"), 10))

        print(entries)

def print_freq(func_count):
    function_dict = {
    0: "KERNEL",
    1: "MALLOC",
    2: "CALLOC",
    3: "REALLOC",
    4: "MMAP",
    5: "POSIX_MEMALIGN",
    6: "VALLOC",
    7: "MEMALIGN",
    8: "PVALLOC",
    9: "ALIGNED_ALLOC",
    10: "FREE",
    11: "MUNMAP"
}
    print("Frequency of each function call:")
    for key,value in func_count.items():
        print(function_dict[key.value],":",value.value)
    
