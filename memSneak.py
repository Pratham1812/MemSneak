from utils.bpf_cli import parse_arguments, get_pid
from utils.bpf_source import generate_bpf_source
from utils.bpf_setup import setup_bpf
from utils.bpf_print import print_outstanding, print_outstanding_combined,print_freq
from time import sleep,time
def main():
    try:
        args = parse_arguments()
    except Exception as e:
        print("Error while parsing arguments: ", e)
        exit(1)
    bpf_source = generate_bpf_source(args)
    try:
        bpf = setup_bpf(args)
    except Exception as e:
        print("Error while setting up BPF: ", e)
        exit(1)
    current_time = time()
    while True:
      if(args.verbose):
          tuple = (bpf.trace_fields(nonblocking=True))
          print(tuple)
          sleep(2)
      else:
        try:
            sleep(args.delay)
            if args.combined:
                print_outstanding_combined(bpf,args.pid,args.sort)
            else:
                print_outstanding(bpf,args.pid,args.sort)
        except KeyboardInterrupt:
            if args.freq:
                print("Frequency of each function call:")
                func_count = bpf["function_count"]
                print_freq(func_count)

            exit(1)
      
        if(time()-current_time>args.duration):
            if args.freq:
                print("Frequency of each function call:")
                func_count = bpf["function_count"]
                print_freq(func_count)
            exit(0)
if __name__ == "__main__":
    main()
    
    

