# Wormhole

The Wormhole index structure was introduced in paper ["Wormhole: A Fast Ordered Index for In-memory Data Management"](https://www.cs.uic.edu/~wuxb/papers/wormhole.pdf)
by Xingbo Wu, Fan Ni, and Song Jiang ([ACM DL](https://dl.acm.org/citation.cfm?id=3303955)).
This repository maintains a reference implementation of the Wormhole index structure.

It supports Linux/FreeBSD/MacOS on x86\_64 and AArch64 CPUs.
On x86\_64, Wormhole requires SSE4.2.
On AArch64, Wormhole requires NEON SIMD and the `crc` features on the target CPU.
The code has been tested with Intel Haswell, Broadwell, and Skylake CPUs.
It has also been tested on a Raspberry PI 4 running 64-bit ArchlinuxArm, and a Jetson Nano running 64-bit Ubuntu Groovy.

## NEWS

* An old limitation about anchor keys has been removed (See Section 3.3 in the original paper for more details).
Now Wormhole can store binary string keys of any patterns including any number of '\0's. A key's length can be 0 to UINT32\_MAX bytes. (Internally: leaf-nodes' anchor key length <= UINT16\_MAX).

* `wh.h` provides a user-friendly interface. See `easydemo.c` for coding examples. the `wh_` functions are thread-safe.

* The `whsafe` API is a *worry-free* thread-safe wormhole API.
At a small cost on each operation, users no longer need to call the `wormhole_refresh_qstate` in any circumstances.

* `merge` (Merge a new kv with existing kv) and `delr` (delete range) operations have been added. They are all thread-safe.

## Highlights:

* Thread-safety: all operations, including `get`, `set`, `inplace-update (inp)`, `del`, `iter-seek`, `iter-peek`, `iter-skip` etc., are thread-safe.
See `stresstest.c` for more thread-safe operations.

* Keys can contain any value, including binary zeros (`'\0'`). Their sizes are always explicitly specified.

* Long keys are welcome! The key-length field (`klen` in `struct kv`) is a 32-bit unsigned integer and the maximum size of a key is 4294967295.

* No background threads or global status. Wormhole uses a mix of user-space rwlocks and QSBR RCU to synchronize between readers and writers.
See below for more details.

# Build

Clang is the default compiler. It can compile with gcc with `$ make CCC=gcc`.
On our testbed, Clang usually produces faster code than GCC.

To build:

    $ make

Alternatively, you may use `O=0g` to enable debug info and disable optimizations:

    $ make O=0g

## Sample programs
`easydemo.c` presents how to use wormhole through a user-friendly API declared at the end of `wh.h`.

    $ ./easydemo.out

The `wh_{ref/unref/get/set/del/probe}` and  `wh_iter_{create/destroy/seek/skip/peek/park/valid}` functions are all thread-safe.
Each thread should acquire a private reference using `wh_ref` for KV operations.

`concbench.out` is an example benchmarking tool of only 150 LoC. See the helper messages for more details.
It generates six-word keys based on a word list (words.txt). See `sprintf` in `concbench.c`.

    $ wget https://github.com/dwyl/english-words/raw/master/words.txt
    $ ./concbench.out words.txt 10000000 4
    $ numactl -N 0 ./concbench.out words.txt 10000000 4

`stresstest.out` tests all thread-safe operations.

`libwh.so` can be linked to any C/C++ program with the help of `wh.h`.

# The wh API (USE THIS)

The `wh_*` functions provides a clean programming interface that helps to avoid common inefficient use of the Wormhole data structure.
If you're not sure which interface to use, just use `wh_*`. Read `easydemo.c` for more details.

Coding examples:

```C
{
    struct wormhole * wh = wh_create(); // create a new wormhole instance
    struct wormref * ref = wh_ref(wh); // to access wh, a thread must obtain a reference
    wh_set(ref, "hello", 5, "world!", 6); // insert a kv pair
    wh_set(ref, NULL, 0, NULL, 0); // both key and value can be zero-sized
    r = wh_probe(ref, "hello", 5); // r == true
    r = wh_probe(ref, NULL, 0); // r == true
    r = wh_probe(ref, "abc", 3); // r == false
    u8 buf [6];
    u32 len_out;
    r = wh_get(ref, "hello", 5, buf, 6, &len_out); // r == true, len_out == 6, "world!" in buf (without trailing zero)
    struct wormhole_iter * iter = wh_iter_create(ref); // creates an iter on a ref
    wh_iter_seek(iter, "h", 1); // seek for the smallest key >= "h"; the iter will be placed on "hello"
    r = wh_iter_valid(iter); // r == true; You should always check if iter is valid after a seek() and skip()
    r = wh_iter_peek(iter, buf, 6, &len_out, NULL, 0, NULL); // only need the key: will get "hello" and 5
    r = wh_iter_peek(iter, NULL, 0, NULL, buf, 6, &len_out); // only need the value: will get "world!" and 6
    // (you can also get both key and value using one call with two buffers)
    wh_iter_skip1(iter); // skip the current key; equivalent to wh_iter_skip(iter, 1);
    r = wh_iter_valid(iter); // r == false; already passed the end of the dataset
    wh_iter_park(iter); // an iter may hold locks; It's a good manner to "park" the iter before sleep. Don't block the intersection!
    sleep(10); // not interacting with the wormhole instance.
    wh_iter_seek(iter, NULL, 0); // need to do another seek to reactivate the iter
    r = wh_iter_valid(iter); // r == true; on the zero-sized key now
    wh_iter_destroy(iter); // now we're done with the iter
    wh_del(ref, "hello", 5); // delete a key
    wh_del(ref, NULL, NULL); // delete the zero-sized key
    wh_unref(ref); // the current thread is no longer interested in accessing the index
    wh_destroy(wh); // fully destroy the index; all references should have been released before calling this
}
```

# Advanced APIs

If the simple and thread-safe `wh_*` interface already meets your performance requirements, You don't need to read the following sections.
Using the `wormhole_*` and `whunsafe_*` APIs can maximize the efficiency of your code with a roughly 5%-10% speedup.
However, inefficient use of these APIs, such as repeatedly calling malloc() to prepare the key buffer, can easily hurt the performance.

## `struct kv` and `struct kref`

There are a handful of helper functions (`kv_*` and `kref_*` functions) at the beginning of wh.h.
It's worth noting that the *key's hash* (`hash` of `struct kv` and `hash32` of `struct kref`)
must be up-to-date before passed to wormhole.
The `kv_refill*` helper functions internally update the hash after filling the kv contents.
In a more general case, `kv_update_hash` directly updates a `struct kv`'s hash.
Similarly, `kref_refill_hash32()` calculates the 32-bit hash for `struct kref`.
Performing the hash calculation at the client side can achieve the best efficiency on the server (the index operations).

## The Wormhole API

`concbench.c` and `stresstest.c` are examples of how to use a Wormhole index.
There are three sets of Wormhole API: `whsafe`, `wormhole`, and `whunsafe`.
* `whsafe`: The *worry-free* thread-safe API. If you use Wormhole in a concurrent environment and want minimal complexity in your code, you should use `whsafe`.
* `wormhole`: The standard thread-safe API. It offers better efficiency than `whsafe` but requires some extra effort for blocking prevention.
* `whunsafe`: the thread-unsafe API. It offers the best speed and efficiency but does not perform internal concurrency control.
External synchronization should be employed when accessing `whunsafe` in a concurrent environment.

The functions of each API can be found near the end of `wh.c` (search `kvmap_api_whsafe`, `kvmap_api_wormhole`, and `kvmap_api_whunsafe`).
Note that each API contains a mix of `whsafe_*`, `wormhole_*`, and `whunsafe_*` functions.

### The `whsafe` API
The `whsafe` API functions are listed in the `kvmap_api_whsafe` structure in `wh.c`. The API consists of a mix of `wormhole_*` and `whsafe_*` functions.

The index operations (GET, SET, UPDATE, DEL, PROBE, INPLACE, MERGE, and SCAN (`wormhole_iter_*` functions)) are all *thread safe*.
A thread needs to hold a reference of the index (_wormref_) to perform safe index operations.

An example of using point-query operations using the `whsafe` API.

```C
{
    wh = wormhole_create(NULL); // use NULL here unless you want to change the allocator.
    ref = whsafe_ref(wh);
    for (...) {
      whsafe_set(ref, ...);
      whsafe_get(ref, ...);
      whsafe_del(ref, ...);
      ... // other safe operations
    }
    ... // other safe operations
    wormhole_unref(ref);
    wormhole_destroy(wh);
}
```

An example of range-query operations:

```C
{
    ref = whsafe_ref(wh);
    // ... assume we already have a valid ref
    iter = wormhole_iter_create(ref);
    for (...) {
      whsafe_iter_seek(iter, key);
      wormhole_iter_peek(iter, buf);
      wormhole_iter_skip(iter, 1);
      wormhole_iter_peek(iter, buf);
      wormhole_iter_skip(iter, 3);
      wormhole_iter_inp(iter, uf, priv);
      // other iter operations
    }
    // An active iterator is likely holding a lock.
    whsafe_iter_park(iter); // Release resources to avoid blocking other threads
    // it's now safe to do something such as sleep() or waitpid()
    // ... start using the iterator again
    whsafe_iter_seek(iter, key2);
    // ... other iter operations
    whsafe_iter_destroy(iter);
    // ... do something
    // must destroy iterators before unref()
    wormhole_unref(ref);
}
```

### The `wormhole` API
Similar to `whsafe`, `wormhole` is also thread safe. It's often faster than `whsafe` but requires extra caution when using it.

An example of using point-query operations using the `wormhole` API.

```C
{
    wh = wormhole_create(NULL); // use NULL here unless you want to change the allocator.
    ref = wormhole_ref(wh);
    for (...) {
      wormhole_set(ref, ...);
      wormhole_get(ref, ...);
      wormhole_del(ref, ...);
      ... // other safe operations
    }
    ... // other safe operations
    wormhole_unref(ref);
    wormhole_destroy(wh);
}
```

An example of range-query operations:

```C
{
    ref = wormhole_ref(wh);
    // ... assume we already have a valid ref
    iter = wormhole_iter_create(ref);
    for (...) {
      wormhole_iter_seek(iter, key);
      wormhole_iter_peek(iter, buf);
      wormhole_iter_skip(iter, 1);
      wormhole_iter_peek(iter, buf);
      wormhole_iter_skip(iter, 3);
      wormhole_iter_inp(iter, uf, priv);
      // other iter operations
    }
    // An active iterator is likely holding a lock.
    wormhole_iter_park(iter); // Release resources to avoid blocking other threads
    while (condition not met) { // See below for explanation
        wormhole_refresh_qstate(ref);
    }
    // ... start using the iterator again
    wormhole_iter_seek(iter, key2);
    // ... other iter operations
    wormhole_iter_destroy(iter);
    // ... do something
    // must destroy iterators before unref()
    wormhole_unref(ref);
}
```

### Avoid blocking writers when using the `wormhole` API
Wormhole internally uses QSBR RCU to synchronize readers/writers so every holder of a reference (`ref`)
needs to actively perform index operations.
An ref-holder, if not actively performing index operations, may block a writer thread that is performing split/merge operations.
(because of not periodically announcing its quiescent state).
If a ref-holder is about to become inactive from Wormhole's perspective (doing something else or just sleeping),
it is recommended that the holder temporarily releases the `ref` before entering the inactive status (such as calling `sleep(10)`),
and reactivate the `ref` before performing the next index operation.

```C
{
    // assume we already have an active ref
    wormhole_park(ref);   // this will avoid blocking any other threads
    sleep(10);
    wormhole_resume(ref);  // this will reactivate the ref
    // continue to perform index operations
}
```

A common scenario of dead-locking is acquiring locks with an active wormhole reference,
The following example could cause deadlock between two threads.

```C
// Thread A has an active ref and try to lock()
{
    struct wormref * ref = wormhole_ref(wh);
    lock(just_a_lock); // << block here forever
}

// Thread B already acquired the lock and wants to insert a key to wh
{
    lock(just_a_lock);
    wormhole_set(ref, kv); << block here forever
}
```

To avoid this scenario, thread A should either call `wormhole_park(ref)` before acquiring the lock, or keep updating the qstate of the ref:
```C
// Solution A.1: use wormhole_park()
{
    struct wormref * ref = wormhole_ref(wh);
    wormhole_park(ref);
    lock(just_a_lock);
    wormhole_resume(ref); // can use ref afterward
}

// Solution A.2: use try_lock and wormhole_refresh_qstate()
{
    struct wormref * ref = wormhole_ref(wh);
    while (!try_lock(just_a_lock)) {
        wormhole_refresh_qstate(ref);
    }
    // continue to use ref
}
```

The above issues with QSBR are specific to the `wormhole` API. `whsafe` does not have these issues.

### The `whunsafe` API
A set of *thread-unsafe* functions are also provided. See the functions with _prefix_ `whunsafe`.
The thread-unsafe functions don't use the reference (_wormref_).
Simply feed them with the pointer to the wormhole index:

```C
{
    wh = whunsafe_create(NULL);
    for (...) {
      whunsafe_set(wh, ...);
      whunsafe_get(wh, ...);
      whunsafe_del(wh, ...);
      ... // other unsafe operations
    }
    ... // other unsafe operations
    wormhole_destroy(wh);
}
```

### In-place update with user-defined function
`wormhole_inp` executes a user-defined function on an existing key-value item.
If the key does not exist, a NULL pointer will be passed to the user-defined function.
A simple example would be incrementing a counter stored in a key-value pair.

```C
{
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
}
```

Note that the user-defined function should ONLY change the value's content, and nothing else.
Otherwise, the index can be corrupted.
A similar mechanism is also provided for iterators (`wormhole_iter_inp`).

The inplace function can also be used to retrieve key-value data. For example:

```C
{
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
}
```

### `merge`: atomic Read-Modify-Write
The `wormhole_merge` and `whsafe_merge` functions perform atomic Read-Modify-Write (RMW) operations.
In a RMW operation, if the search key is found, the KV pair will be passed to a user-defined callback function `uf` (short for user function).
Otherwise, a NULL pointer is passed to `uf`.
`uf` could update the KV in-place if it does not require any memory reallocation.
In such a case, `uf` should return the KV's pointer back and the merge function will do nothing else.
If `uf` want to replace the KV with something new, it should return a pointer that is different than the original KV pointer.
The `uf` should not make memory allocation by itself.
Instead, the `merge` function will copy the returned KV and replace the existing KV with the newly created one.
`uf` should not return NULL unless the key was not found.

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

```C
{
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
}
```

Each of the in/out/free functions can be freely customized.
A few `kvmap_mm_*` functions are already provided for common scenarios.
`kvmap_mm_ndf` is identical to the `kvmap_mm_ualloc` structure in the above example.

## Hugepages
Wormhole uses hugepages when available. To reserve some hugepages in Linux (10000 * 2MB):

    # echo 10000 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# Tuning

A few macros in `wh.c` can be tuned.

* `WH_SLABLEAF_SIZE` controls the slab size for leaf node allocation.
The default is `((1lu << 21))` (2MB slabs). If 1GB hugepages are available, `WH_SLABLEAF_SIZE` can be set to `((1lu << 30))` to utilize 1GB hugepages.
Using 1GB hugepages can improve search performance on a large dataset.

* `WH_KPN` controls "Keys Per (leaf-)Node". The default value is 128.
Compared to the default, `WH_KPN=256` can offer 5-10%+ higher search/update speed.
However, random insertions can be slower due to more expensive sorting in each node.

* `QSBR_STATES_NR` and `QSBR_SHARDS_NR` control the capacity (number of active references) of the QSBR RCU.
The product of the two values is the capacity. For efficiency, `QSBR_STATES_NR` can be set to 23, 39, and 55, and `QSBR_SHARDS_NR` must be 2^n, n<=6.
The defaults are 23 and 32, respectively. The QSBR registry can run out of space if there are a few hundred of threads, which is not a problem in practice.

# Limitations

## Key Patterns
A **split** operation will fail when **129** (`WH_KPN + 1`) keys share a common prefix of 65535+ bytes.
In Wormhole, the maximum _anchor-key_ length is 65535 (2^16) bytes, which is shorter than the maximum key-length (2^32).

## Memory Allocation
Insertions/updates can fail and return false when a memory allocation fails.
On memory-allocation failure, the hash-table expansion function will block and wait for available memory.

# Performance
Some benchmarking results with some real-world datasets: See [this](https://github.com/wuxb45/wormhole/issues/5) page for more information.

![Concurrent GET](https://user-images.githubusercontent.com/564235/112712778-704d7200-8e9f-11eb-9f4d-795de46772d1.png)
