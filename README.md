# Wormhole

The Wormhole index structure was introduced in paper ["Wormhole: A Fast Ordered Index for In-memory Data Management"](https://www.cs.uic.edu/~wuxb/papers/wormhole.pdf) by Xingbo Wu, Fan Ni, and Song Jiang ([ACM DL](https://dl.acm.org/citation.cfm?id=3303955)).

This repository maintains a reference implementation of the Wormhole index structure on x86\_64 Linux with SSE 4.2.
The implementation has been well tuned on Xeon E5-26xx v4 CPUs with some aggressive optimizations.

## Highlights:
* Thread-safety: all operations, including `get`, `set`, `inplace-update`, `del`, `iter-seek`, `iter-next`, etc., are thread-safe. See `stresstest.c` for more thread-safe operations.
* Keys can contain any value, including binary zeros (`'\0'`). Their sizes are always explicitly specified in `struct kv`.
* Long keys are welcome! The key-length field (`klen` in `struct kv`) is a 32-bit unsigned integer and the maximum size of a key is 4294967295.
* No background threads or global status. Wormhole uses a mix of user-space rwlocks and QSBR RCU to synchronize between readers and writers. See below for more details.

# Build

Wormhole was developed & tested on x86\_64 Linux.
Clang is the default compiler. It can be changed to gcc in `Makefile` (`$ CCC=gcc make`).

To build:

    $ make

Alternatively, you may use `O=0g` to enable debug info and disable optimizations:

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
A better solution can be used if the ref-holder thread can periodically update its quiescent state by calling `wormhole_refresh_qstate()`.
This method has negligible cost (only two instructions).
For example:

    // holding a ref
    while (wait_for_client_with_timeout_10us(...)) {
      wormhole_refresh_qstate(ref);  // only two mov instructions on x86_64
    }
    // perform index operations with ref

### The thread-unsafe API
A set of *thread-unsafe* functions are also provided. See the functions with _prefix_ `whunsafe`.
The thread-unsafe functions don't use the reference (_wormref_). Simply feed it with the pointer to the wormhole index:

    index = whunsafe_create(NULL);
    for (...) {
      whunsafe_set(index, ...);
      whunsafe_get(index, ...);
      whunsafe_del(index, ...);
      ... // other unsafe operations
    }
    ... // other unsafe operations
    wormhole_destroy(index);

### Light-weight GET functions
`wormhole_get()` returns a full copy of the key-value pair to the user-provided buffer (or malloc-ed if `out == 0`).
This can be suboptimal when dealing with long keys and short values.
To minimize copying, the `wormhole_getv` and `wormhole_getu64` functions avoid copying the key.

`wormhole_getu64` returns 0 if the key if not found or the value's length is shorter than 8 bytes.
This can be useful if the application logic treats "`value == 0`" as equivalent to "not found".

### In-place update with user-defined function
`wormhole_inplace` executes a user-defined function on an existing key-value item.
If the key does not exist, a NULL pointer will be passed to the user-defined function.
A simple example would be incrementing a counter stored in a key-value pair.

    // user-defined in-place update function
    void myadd1(struct kv * kv, void * priv) {
      if (kv != NULL) {
        assert(kv->vlen >= sizeof(u64));
        u64 * pvalue = kv_vptr(kv0);
        (*pvalue)++;
      }
    }

    // create the counter
    u64 zero = 0;
    struct kv * tmp = kv_create("counter", 7, &zero, 8); // malloc-ed
    wormhole_set(ref, tmp);
    free(tmp);

    // perform +1
    struct kv * key = kv_create("counter", 7, NULL, 0); // malloc-ed
    wormhole_update(ref, key, myadd1, NULL);
    free(key);

Note that the user-defined function should ONLY change the value's content, and nothing else.
Otherwise, the index can be corrupted.
A similar mechanism is also provided for iterators (`wormhole_iter_inplace`).

### Iterator
The `wormhole_iter_{seek,peek,skip,next,inplace}` functions provide range-search functionalities.
If the search key does not exist, the `seek` operation will put the cursor on the item that is greater than the search-key.
`next` will return the item under the current cursor and move the cursor forward. `peek` is similar but does not move the cursor. For example, with keys `{1,3,5}`, `seek(2); r = next()` will see `r == 3`.

Currently Wormhole does not provide `seek_for_less_equal()` and `prev()` for backward scanning. This feature will be added in the future.

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


## Tuning
A few macros in `wh.c` can be tuned.
* `WH_SLABLEAF_SIZE` controls the slab size for leaf node allocation.  The default is `((1lu << 21))` (2MB slabs). If 1GB hugepages are available, `WH_SLABLEAF_SIZE` can be set to `((1lu << 30))` to utilize those 1GB hugepages.
* `WH_KPN` controls "Keys Per (leaf-)Node". The default value is 128. Setting it to 256 can increase search speed by roughly 10% but slows down internal split/merge operations (but not every insertion/deletion).
* `QSBR_STATES_NR` and `QSBR_SHARDS_NR` control the capacity (number of references) of the QSBR RCU. The product of the two values is the capacity. For efficiency, `QSBR_STATES_NR` can be set to 22, 38, and 54, and `QSBR_SHARDS_NR` must be 2^n. The defaults are set to 38 and 8, respectively. This QSBR implementation uses sharding so `wormhole_ref()` will block (busy-waiting) if the target shard is full.

## Limitations

### Key Patterns
The Wormhole index works well with real-world keys.
A **split** operation may fail with one of the following (almost impossible) conditions:
* The maximum _anchor-key_ length is 65535 bytes (represented by a 16-bit value), which is shorter than the maximum key-length (32-bit). Split will fail if all cut-points in the target leaf node require longer anchor-keys. In such case, at least **129** (`WH_KPN + 1`) keys must share a common prefix of 65535+ bytes.
* Two anchor-keys cannot be identical after removing their trailing zeros. To be specific, `"W"` and `"Worm"` can be anchor-keys at the same time, but `"W"` and `"W\0\0"` cannot (while these two keys can co-exist as regular keys). If there are at least **129** (`WH_KPN + 1`) keys shareing the same prefix but having ONLY different numbers of trail zeros (having `"W"`, `"W\0"`, `"W\0\0"`, `"W\0\0\0"` ... and finally a 'W' with at least 128 trailing zeros), the split will fail.

### Memory Allocation
Insertions can also fail if there is not enough memory. The current implementation can safely return after any failed memory allocation, except for hash-table expansion (resizing). On memory-allocation failure, the expansion function will block and wait for available memory to proceed. In the future, this behavior will be changed to directly return with a failure.

## Performance
Some benchmarking results with some real-world datasets: See [this](https://github.com/wuxb45/wormhole/issues/5) page for more information.

![Concurrent GET](https://user-images.githubusercontent.com/564235/65991356-d300b180-e452-11e9-9103-f0f7e8dae20b.png)
