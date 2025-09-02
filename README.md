# a-simple-FreeBSD-kernel-module


## Description

This project is based on FreeBSD 14.0-RELEASE and this is a simple FreeBSD kernel module. This module registers itself as a MAC policy module and has the following functionality:

1. Every open request on a file containing the extended attribute ```user.secure``` will be denied.
2. If such a request happened, the requesting process will be marked as ```tainted```.
3. All requests to remove extended attributes by a process marked ```tainted``` (or one of its descendants) on a file containing the extended attribute ```user.secure``` will be denied.
4. This mudule cleanly unloadable - no memory leaks!
5. Everything is appropriately synchronized, this module is not subject to race-conditions.


## Usage 
#### make

```shell
make
sudo kldload ./simple_module.ko
```

Using the following command, you can confirm that simple_module has indeed been added to the list

```shell
kldstat
```

#### test

```shell
vim a.txt # Create a new file a.txt, write something and save it
vim b.txt # Create a new file b.txt, write something and save it
sudo getextattr user secure a.txt # Output: "getextattr: a.txt: failed: Attribute not found" , which means the 'secure' attribute is not set
sudo setextattr user secure 1 a.txt # Set the 'secure' attribute to a.txt
sudo getextattr user secure a.txt # Now a.txt has the 'secure' attribute set to 1
cat a.txt  # Output: “cat: a.txt: Operation not permitted”, because the thread attempts to open a file with user.secure attribute


# I also wrote a small C program that executes two operations,this ensures that the open and deleteextattr actions share the same PID context and trigger the taint-checking logic as expected.
cc -o small_test small_test.c
 ./small_test # Attribute 'user.secure' deleted successfully.
```



```shell
sudo setextattr user secure 1 b.txt
sudo setextattr user secure 1 a.txt
./small_test
# Output:
# open: Operation not permitted
# extattr_delete_file: Operation not permitted
# It accesses b.txt which has the secure attribute,
# so the process is marked as tainted, and therefore cannot delete the secure attribute of a.txt
```

#### unload

```shell
sudo kldunload simple_module.ko
```

You can view the list of all modules and confirm that it has indeed been removed:

```shell
kldstat
```



## Reference

https://docs.freebsd.org/en/books/arch-handbook/mac/

https://github.com/AmbrSb/XAC/blob/main/kernel/mac_xac.c

https://github.com/martin-beran/mac_sofi/blob/master/mac_sofi/mac_sofi.c
