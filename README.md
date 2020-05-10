# Wormhole

The Wormhole index structure was introduced in paper ["Wormhole: A Fast Ordered Index for In-memory Data Management"](https://www.cs.uic.edu/~wuxb/papers/wormhole.pdf) by Xingbo Wu, Fan Ni, and Song Jiang ([ACM DL](https://dl.acm.org/citation.cfm?id=3303955)).

This repository maintains a reference implementation of the Wormhole index structure on x86\_64 Linux/FreeBSD with SSE 4.2.
The implementation has been well tuned on Xeon E5-26xx v4 CPUs with some aggressive optimizations.

Experimental ARM64(AArch64) support has been added. The code has not been optimized for ARM64.

## Highlights:
* (New) `merge` (Merge a new kv with existing kv) and `delr` (delete range) operations have been added. They are all thread-safe.
* Thread-safety: all operations, including `get`, `set`, `inplace-update (inp)`, `del`, `iter-seek`, `iter-peek`, `iter-skip` etc., are thread-safe. See `stresstest.c` for more thread-safe operations.
* Keys can contain any value, including binary zeros (`'\0'`). Their sizes are always explicitly specified in `struct kv`.
* Long keys are welcome! The key-length field (`klen` in `struct kv`) is a 32-bit unsigned integer and the maximum size of a key is 4294967295.
* No background threads or global status. Wormhole uses a mix of user-space rwlocks and QSBR RCU to synchronize between readers and writers. See below for more details.

# Build

## x86\_64
Wormhole is developed & tested on x86\_64 Linux and FreeBSD.
Clang is the default compiler. It can be changed to gcc in `Makefile` (`$ make CCC=gcc`).
On our testbed Clang usually produces faster code.

To build:

    $ make

Alternatively, you may use `O=0g` to enable debug info and disable optimizations:

    $ make O=0g

Read `Makefile.common` for options on optimization and debugging levels (O=).

## ARM64 (experimental)

Wormhole now builds on 64-bit ARM (aarch64). The currect implementation requires NEON SIMD and the `crc` features on the target CPU. The Clang in our testbed (clang-8, Ubuntu 18.04) does not support `-march=native` so the target needs to be explicitly specified.

    $ make CCC=clang-8 ARCH=armv8-a+crc

## Sample programs
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

## `struct kv` and `struct kref`

Please refer to demo1.c for quick examples of how to manipulate the *key-value* (`struct kv`)
and the *key-reference* (`struct kref`).
There are a handful of helper functions (`kv_*` and `kref_*` functions) at the beginning of wh.h.

It's worth noting that the *key's hash* (`hash` of `struct kv` and `hash32` of `struct kref`)
must be up-to-date before passed to wormhole.
The `kv_refill*` helper functions internally update the hash after filling the kv contents.
In a more general case, `kv_update_hash` directly updates a `struct kv`'s hash.
Similarly, `kref_refill_hash32()` calculates the 32-bit hash for `struct kref`.

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
The thread-unsafe functions don't use the reference (_wormref_).
Simply feed them with the pointer to the wormhole index:

    index = whunsafe_create(NULL);
    for (...) {
      whunsafe_set(index, ...);
      whunsafe_get(index, ...);
      whunsafe_del(index, ...);
      ... // other unsafe operations
    }
    ... // other unsafe operations
    wormhole_destroy(index);

### In-place update with user-defined function
`wormhole_inp` executes a user-defined function on an existing key-value item.
If the key does not exist, a NULL pointer will be passed to the user-defined function.
A simple example would be incrementing a counter stored in a key-value pair.

    // user-defined in-place update function
    void myadd1(struct kv * kv, void * priv) {
      if (kv != NULL) {
        assert(kv->vlen >= sizeof(u64));
        u64 * pvalue = kv_vptr(kv);
        (*pvalue)++;
      }
    }

    // create the counter
    u64 zero = 0;
    struct kv * tmp = kv_create("counter", 7, &zero, 8); // malloc-ed
    wormhole_set(ref, tmp);

    // perform +1 on the stored value
    struct kref kref = kv_ref(tmp); // create a kref of tmp
    wormhole_inp(ref, &kref, myadd1, NULL);

Note that the user-defined function should ONLY change the value's content, and nothing else.
Otherwise, the index can be corrupted.
A similar mechanism is also provided for iterators (`wormhole_iter_inp`).

The inplace function can also be used to retrieve key-value data. For example:

    void inplace_getu64(struct kv * kv, void * priv) {
      if (kv != NULL) {
        assert(kv->vlen >= sizeof(u64));
        u64 * pvalue = kv_vptr(kv);
        *(u64 *)priv = *pvalue;
      } else {
        *(u64 *)priv = 0;
      }
    }
    ...
    struct kref kref = ...
    u64 val;
    wormhole_inp(ref, &kref, inplace_getu64, &val);

### Iterator
The `wormhole_iter_{seek,peek,skip,next,inp}` functions provide range-search functionalities.
If the search key does not exist, the `seek` operation will put the cursor on the item that is greater than the search-key.
`next` will return the item under the current cursor and move the cursor forward.
`peek` is similar but does not move the cursor. For example, with keys `{1,3,5}`, `seek(2); r = next()` will see `r == 3`.

Currently Wormhole does not provide `seek_for_less_equal()` and `prev()` for backward scanning. This feature will be added in the future.

# Memory management

By default, Wormhole manages all the key-value data internally and only copies to or from a user-supplied
buffer (a `struct kv` object).
This draws a clear boundary in the memory space between the index structure and its users.
After a call to any of the index operations, the caller can immediately free
the buffer holding the key-reference or the key-value data.
This also allows users to use stack-allocated variables to interact with Wormhole.

The memory manager of the internal key-value objects can be customized when creating a new Wormhole (see `wormhole_create`).
The customization will _only_ affect the internal `struct kv` objects.
Actually, the memory manager can be configured to directly use the caller's `struct kv` object and store it in Wormhole.
This `struct kvmap_mm` structure shows an example:

    const struct kvmap_mm kvmap_mm_ualloc {
      .in = kvmap_mm_in_noop, // in wormhole_set(), store caller's kv in wh
      .out = kvmap_mm_out_dup, // but still make a copy in wormhole_get()
      .free = kvmap_mm_free_free, // call free() for delete/update
    };
    ...
    struct wormhole * wh = wormhole_create(&kvmap_mm_ualloc);
    struct wormref * ref = wormhole_ref(wh);
    ...
    struct kv * newkv = malloc(size);
    ...
    wormhole_set(ref, newkv);
    // Don't free newkv! it's now managed by wh

Each of the in/out/free functions can be freely customized.
A few `kvmap_mm_*` functions are already provided for common scenarios.

## Hugepages
Wormhole uses hugepages when available. To reserve some hugepages in Linux (10000 * 2MB):

    # echo 10000 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages


# Tuning
A few macros in `wh.c` can be tuned.
* `WH_SLABLEAF_SIZE` controls the slab size for leaf node allocation.  The default is `((1lu << 21))` (2MB slabs). If 1GB hugepages are available, `WH_SLABLEAF_SIZE` can be set to `((1lu << 30))` to utilize those 1GB hugepages.
* `WH_KPN` controls "Keys Per (leaf-)Node". The default value is 128. Setting it to 256 can increase search speed by roughly 10% but slows down internal split/merge operations (but not every insertion/deletion).
* `QSBR_STATES_NR` and `QSBR_SHARDS_NR` control the capacity (number of references) of the QSBR RCU. The product of the two values is the capacity. For efficiency, `QSBR_STATES_NR` can be set to 22, 38, and 54, and `QSBR_SHARDS_NR` must be 2^n. The defaults are set to 38 and 8, respectively. This QSBR implementation uses sharding so `wormhole_ref()` will block (busy-waiting) if the target shard is full.

# Limitations

## Key Patterns
The Wormhole index works well with real-world keys.
A **split** operation may fail with one of the following (almost impossible) conditions:
* The maximum _anchor-key_ length is 65535 bytes (represented by a 16-bit value), which is shorter than the maximum key-length (32-bit). Split will fail if all cut-points in the target leaf node require longer anchor-keys. In such case, at least **129** (`WH_KPN + 1`) keys must share a common prefix of 65535+ bytes.
* Two anchor-keys cannot be identical after removing their trailing zeros. To be specific, `"W"` and `"Worm"` can be anchor-keys at the same time, but `"W"` and `"W\0\0"` cannot (while these two keys can co-exist as regular keys). If there are at least **129** (`WH_KPN + 1`) keys shareing the same prefix but having ONLY different numbers of trail zeros (having `"W"`, `"W\0"`, `"W\0\0"`, `"W\0\0\0"` ... and finally a 'W' with at least 128 trailing zeros), the split will fail.

## Memory Allocation
Insertions can also fail if there is not enough memory. The current implementation can safely return after any failed memory allocation, except for hash-table expansion (resizing). On memory-allocation failure, the expansion function will block and wait for available memory to proceed. In the future, this behavior will be changed to returning with an insertion failure.

# Performance
Some benchmarking results with some real-world datasets: See [this](https://github.com/wuxb45/wormhole/issues/5) page for more information.

![Concurrent GET](https://user-images.githubusercontent.com/564235/65991356-d300b180-e452-11e9-9103-f0f7e8dae20b.png)
