bigmalloc
=========

This test verifies creation of an enclave with 16 gigabytes of heap. The
enclave then attempts to allocate 99% of its heap with **oe_malloc()**.

This test requires approximately 64 gigabytes of system memory (RAM plus swap
space), else the test exits (with success) with a warning.

On Linux systems, use the following command to determine total system memory.

```
free -m
```

If the sum of RAM and swap space is less than 64 gigabytes, then add additional
swap space with the following commands.

```
# Create a 64 GB file that is filled with zeros.
dd if=/dev/zero of=/swapfile bs=1024 count=64M

# Initialize with a swap file system.
mkswap /swapfile

# Make the swap file readable by root.
chmod 0600 /swapfile

# Add the swap space.
swapon /swapfile
```
