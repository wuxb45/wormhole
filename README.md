# Wormhole

The Wormhole index structure was introduced in paper ["Wormhole: A Fast Ordered Index for In-memory Data Management"](https://www.cs.uic.edu/~wuxb/papers/wormhole.pdf) by Xingbo Wu, Fan Ni, and Song Jiang ([ACM DL](https://dl.acm.org/citation.cfm?id=3303955)).

This repository maintains a reference implementation of the Wormhole index structure on x86\_64 Linux with SSE 4.2.
The implementation has been well tuned on Xeon E5-26xx v4 CPUs with some aggressive optimizations.

Please read this README and the sample programs before using Wormhole in your code.

# Build

The project was developed & tested on a 64-bit Linux.
Some Linux-specific APIs are used (e.g., `mmap`) so porting to MacOS/Windows may take some effort.
Clang is the default compiler. It can be changed to gcc in Makefile.common (CCC=gcc make).

To build:

    $ make

Alternatively, you may use `O=0g` to enable debug info and disable optimization:

    $ O=0g make

Read Makefile.common for options on optimization and debugging levels (O=).

To run the demo code:

    $ ./demo1.out <a text file>

Each line of the input becomes a key in the index. Duplicates are allowed from the input. You may use "wh.c" for a test drive.

`concbench.out` is an example benchmarking tool of only 150 LoC. See the helper messages for more details.
It generates keys based on a word list (words.txt). See the key pattern used in `sprintf` in `concbench.c`.

    $ wget https://github.com/dwyl/english-words/raw/master/words.txt
    $ numactl -N 0 ./concbench.out words.txt 10000000 4

# The code

## `struct kv`

Please refer to demo1.c for quick examples of how to manipulate the *key-value* objects (`struct kv`).
The `struct kv` is also used to represent a *key*, where the value portion is simply ignored.
There are a handful of helper functions (kv\_\* functions) provided in wh.c.

It's worth noting that the *key's hash* in a `struct kv` must be up-to-date before the key in the
`struct kv` object is used by wormhole functions.
The `kv_refill*` helper functions internally update the hash.
In a more general case, `kv_update_hash` can be used to update the key's hash.

## The Wormhole API

The Wormhole functions are listed near the bottom of wh.h (see the wormhole\_\* functions).
`demo1.c` and `concbench.c` privide examples of how to use the Wormhole index.

### The thread-safe API
The default index operations (GET, SET, DEL, PROBE, and SCAN (wormhole\_iter\_\* functions)) are *thread safe*.
Each thread needs to hold a reference of the index (_wormref_) to perform the index operations. For example:

    index = wormhole_create(NULL); // use NULL here unless you want to change the allocator.
    ref = wormhole_ref(index);
    for (...) {
      wormhole_get(ref, ...);
    }
    ... // other index operations
    wormhole_unref(ref);
    wormhole_destroy(index);

Wormhole internally uses QSBR RCU to synchronize readers/writers so every holder of a reference (`ref`)
needs to actively perform index operations.
An ref-holder, if not actively performing index operations, may block writer threads (because of not periodically announcing its quiescent state).
If a ref-holder is about to become inactive (regarding to performing Wormhole operations),
it is recommended that the holder temporarily releases the `ref` before entering the inactive status (such as calling `sleep(10)`), and obtain a new `ref` after that.

### The thread-unsafe API
A set of *thread-unsafe* functions are also provided. See the functions with "\_unsafe" suffix.
The thread-unsafe functions don't use the reference (_wormref_). Simply feed it with the pointer to the wormhole index:

    index = wormhole_create(NULL);
    for (...) {
      wormhole_get_unsafe(index, ...);
    }
    // other unsafe operations
    wormhole_destroy(index);

## Memory management

Wormhole manages all the key-value data internally and only copies to or from a user-supplied
buffer (a `struct kv` object).
This draws a clear boundary in the memory space between the index structure and its users.
After a call to any of the index operations, the caller can immediately free
the buffer holding the key or the key-value data.
This also allows users to use stack-allocated `struct kv` objects to interact with Wormhole.

The memory allocator for the internal key-value data can be customized when the index is created/initialized (see `wormhole_create`).
The allocator will _only_ be used for allocating the internal key-value data (the `struct kv` objects),
but not the other objects in Wormhole, such as hash table and tree nodes.

### Hugepages
Wormhole uses hugepages when available. To reserve some hugepages in Linux (10000 * 2MB):

    # echo 10000 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

## Performance
Some benchmarking results with some real-world datasets: See [this](https://github.com/wuxb45/wormhole/issues/5) page for more information.

![Concurrent GET](https://user-images.githubusercontent.com/564235/65991356-d300b180-e452-11e9-9103-f0f7e8dae20b.png)
