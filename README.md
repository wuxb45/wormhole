# Wormhole

The Wormhole index structure was introduced in paper ["Wormhole: A Fast Ordered Index for In-memory Data Management"](https://www.cs.uic.edu/~wuxb/papers/wormhole.pdf) by Xingbo Wu, Fan Ni, and Song Jiang ([ACM DL](https://dl.acm.org/citation.cfm?id=3303955)).

This repository maintains a reference implementation of the Wormhole index structure on x86\_64 Linux with SSE 4.2.
The implementation has been well tuned on Xeon E5-26xx v4 CPUs with some aggressive optimizations.

## Highlights:
* Thread-safety: `get`, `set`, `update`, `del`, `iter-seek`, `iter-next`, etc. are all thread-safe. See `stresstest.c` for more operations.
* Long keys are welcome! The key-length field (`klen`) is a 32-bit unsigned integer and the maximum size of a key is 4GB.
* No background threads or global status. Wormhole uses user-space rwlocks and QSBR RCU to synchronize between readers and writers. See below for more details.

# Build

Wormhole was developed & tested on x86\_64 Linux.
Clang is the default compiler. It can be changed to gcc in `Makefile` (`$ CCC=gcc make`).

To build:

    $ make

Alternatively, you may use `O=0g` to enable debug info and disable optimizations (very slow):

    $ O=0g make

Read `Makefile` for options on optimization and debugging levels (O=).

To run the demo code:

    $ ./demo1.out <a text file>

Each line in the text file becomes a key. Duplicates are allowed. You may use "wh.c" for a quick test drive.

`concbench.out` is an example benchmarking tool of only 150 LoC. See the helper messages for more details.
It generates six-word keys based on a word list (words.txt). See `sprintf` in `concbench.c`.

    $ wget https://github.com/dwyl/english-words/raw/master/words.txt

    $ ./concbench.out words.txt 10000000 4

    $ numactl -N 0 ./concbench.out words.txt 10000000 4

`stresstest.out` tests all thread-safe operations.

`libwh.so` can be linked to any C/C++ program with the help of `wh.h`.

# The code

## `struct kv`

Please refer to demo1.c for quick examples of how to manipulate the *key-value* objects (`struct kv`).
The `struct kv` is also used to represent a *key*, where the value portion is simply ignored.
There are a handful of helper functions (`kv_*` functions) provided in wh.c.

It's worth noting that the *key's hash* in a `struct kv` must be up-to-date before the key in the
`struct kv` object is used by wormhole functions.
The `kv_refill*` helper functions internally update the hash after filling the kv contents.
In a more general case, `kv_update_hash` directly updates the key's hash.

## The Wormhole API

The Wormhole functions are listed near the bottom of wh.h (see the `wormhole_*` functions).
`demo1.c` and `concbench.c` are examples of how to use the Wormhole index.

### The thread-safe API
The index operations (GET, SET, UPDATE, DEL, PROBE, and SCAN (`wormhole_iter_*` functions)) are all *thread safe*.
A thread needs to hold a reference of the index (_wormref_) to perform safe index operations. For example:

    index = wormhole_create(NULL); // use NULL here unless you want to change the allocator.
    ref = wormhole_ref(index);
    for (...) {
      wormhole_set(ref, ...);
      wormhole_get(ref, ...);
      wormhole_del(ref, ...);
      ... // other safe operations
    }
    ... // other safe operations
    wormhole_unref(ref);
    wormhole_destroy(index);

### Avoid blocking writers
Wormhole internally uses QSBR RCU to synchronize readers/writers so every holder of a reference (`ref`)
needs to actively perform index operations.
An ref-holder, if not actively performing index operations, may block a writer thread that is performing split/merge operations.
(because of not periodically announcing its quiescent state).
If a ref-holder is about to become inactive from Wormhole's perspective (doing something else or just sleeping),
it is recommended that the holder temporarily releases the `ref` before entering the inactive status (such as calling `sleep(10)`),
and obtains a new `ref` before performing the next index operation.

    // holding a ref
    wormhole_unref(ref);
    sleep(10);
    ref = wormhole_ref(map);
    // perform index operations with (the new) ref

However, frequently calling `wormhole_ref()` and `wormhole_unref()` can be expensive because they acquire locks internally.
A better solution is available if the ref-holder thread is able to periodically update its quiescent state by call `wormhole_refresh_qstate()`. This method has negligible cost (only two instructions) and does not interfere with other threads.
For example:

    // holding a ref
    while (wait_for_client_with_timeout_10us(...)) {
      wormhole_refresh_qstate(ref);  // only two mov instructions on x86_64
    }
    // perform index operations with ref

### The thread-unsafe API
A set of *thread-unsafe* functions are also provided. See the functions with suffix `_unsafe`.
The thread-unsafe functions don't use the reference (_wormref_). Simply feed it with the pointer to the wormhole index:

    index = wormhole_create(NULL);
    for (...) {
      wormhole_set_unsafe(index, ...);
      wormhole_get_unsafe(index, ...);
      wormhole_del_unsafe(index, ...);
      ... // other unsafe operations
    }
    ... // other unsafe operations
    wormhole_destroy(index);

### light-weight GET functions
`wormhole_get()` returns a full copy of the key-value pair to the user-provided buffer (or malloc-ed if `out == 0`). This can be suboptimal when dealing with long keys and short values.
To minimize copying, the `wormhole_getv` and `wormhole_getu64` functions avoid copying the key.

`wormhole_getu64` returns 0 if the key if not found or the value's length is shorter than 8 bytes. This can be useful if the application logic treats "`value == 0`" as equivalent to "not found".

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
