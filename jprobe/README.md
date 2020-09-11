# jprobe

```
cd jprobe_xxx
scl enable devtoolset-2 make

# if objtool is missing, copy it from kernel build.
sudo cp objtool /lib/modules/$(uname -r)/build/tools/objtool/
```

```
sudo insmod /path/to/jprobe_xxx/jprobe_xxx.ko
sudo rmmod  /path/to/jprobe_xxx/jprobe_xxx.ko
```

c.f. https://www.kernel.org/doc/Documentation/kprobes.txt
