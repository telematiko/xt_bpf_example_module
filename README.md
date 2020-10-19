# xt_bpf_example_module
Example of ebpf program for iptables xt_bpf module.
Based on `samples/bpf/sockex3_kern.c`

### Test procedure

Prepare development enviroment and download linux-sources, build bpftools.
Copy `bpf_prog1.c` to `./linux-source/samples/bpf/` directory.
In `samples/bpf/Makefile` add `always-y += bpf_prog1.o`
Clear test data:
```sh
$ iptables -F && rm -f /sys/fs/bpf/bpf_prog1 &&  make -C samples/bpf clean
```
Make program:
```sh
$ cd ./linux-source/
$ make M=samples/bpf
```
Load bpf program and iptables rules:
```sh
$ bpftool prog load samples/bpf/bpf_prog1.o /sys/fs/bpf/prog1 type socket
$ iptables -A INPUT  -p tcp -m tcp --dport 8000 -m bpf --object-pinned /sys/fs/bpf/prog1 -j LOG 
$ iptables -A INPUT -p udp -m udp --dport 1234 -m bpf --object-pinned /sys/fs/bpf/prog1 -j LOG
```
Run TCP and UDP servers:
```
$ python3 -m http.server &
$ nc -lu 1234 &
```

Send requests to listened servers from other machine:
```
$ curl http://$srv:8000/
$ echo -ne '\x00\x00\x1F\x45' | nc -u $srv 1234 
```

View hash_map dump with parsed data:
```
$ bpftool m dump id `bpftool m | grep hash_map | cut -d':' -f 1`
```
