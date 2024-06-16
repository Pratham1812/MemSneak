## MemSneak

This tool is used to sneak for memory leaks in a process. It traces outstanding memory allocations that were not freed by a process.
It supports both user mode allocations and kernel mode allocations. Currently supporting memory allocation performed with various libc functions and also kernel mode functions like `kmalloc/kmem_cache_alloc/get_free_pages`.

It also maintains the count of various memory allocation functions.

# Setup
You must have bcc installed on your machine in order to run this tracer.

To install `bcc`, follow the instructions given on this [link](https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---source).

Clone the repository and navigate to the folder.
Then run
```
pip install -r requirements.txt
```

# Running the tool
Possible options
![image](https://github.com/Pratham1812/MemSneak/assets/32198580/c4767fcd-e4ee-4167-8cf6-dc8ef3412cef)


To run sample binary in `examples/` directory

```
sudo python3 memSneak.py -c "./example/main" 
```
Pass the `--freq` flag to count the frequency of each allocation
![image](https://github.com/Pratham1812/MemSneak/assets/32198580/bea428cc-4c1d-430b-b8d3-74e91adfe5a7)


To run the tool on all the kernel processes

```
sudo python3 memSneak.py
```
![image](https://github.com/Pratham1812/MemSneak/assets/32198580/88b7c1de-4215-4308-835d-f427c7d663dd)

To run the tool for specific PID

```
sudo python3 memSneak.py -p <PID>
```

To lookout for more options 
```
sudo python3 memSneak.py -h
```





