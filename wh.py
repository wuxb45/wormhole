#!/usr/bin/python3

#
# Copyright (c) 2016--2021  Wu, Xingbo <wuxb45@gmail.com>
#
# All rights reserved. No warranty, explicit or implicit, provided.
#

import msgpack
from ctypes import *   # CDLL and c_xxx types

# libwh {{{
# Change this path when necessary
libwh = CDLL("./libwh.so")

# create
libwh.wh_create.argtypes = []
libwh.wh_create.restype = c_void_p

# close (no return value)
libwh.wh_destroy.argtypes = [c_void_p]

# ref
libwh.wh_ref.argtypes = [c_void_p]
libwh.wh_ref.restype = c_void_p

# unref
libwh.wh_unref.argtypes = [c_void_p]

# put
libwh.wh_put.argtypes = [c_void_p, c_char_p, c_uint, c_char_p, c_uint]
libwh.wh_put.restype = c_bool

# get
libwh.wh_get.argtypes = [c_void_p, c_char_p, c_uint, c_char_p, c_uint, c_void_p]
libwh.wh_get.restype = c_bool

# probe
libwh.wh_probe.argtypes = [c_void_p, c_char_p, c_uint]
libwh.wh_probe.restype = c_bool

# del
libwh.wh_del.argtypes = [c_void_p, c_char_p, c_uint]
libwh.wh_del.restype = c_bool

# iter_create
libwh.wh_iter_create.argtypes = [c_void_p]
libwh.wh_iter_create.restype = c_void_p

# iter_seek
libwh.wh_iter_seek.argtypes = [c_void_p, c_char_p, c_uint]

# iter_valid
libwh.wh_iter_valid.argtypes = [c_void_p]
libwh.wh_iter_valid.restype = c_bool

# iter_skip1
libwh.wh_iter_skip1.argtypes = [c_void_p]

# iter_skip
libwh.wh_iter_skip.argtypes = [c_void_p, c_uint]

# iter_peek
libwh.wh_iter_peek.argtypes = [c_void_p, c_char_p, c_uint, c_void_p, c_char_p, c_uint, c_void_p]
libwh.wh_iter_peek.restype = c_bool

# iter_park
libwh.wh_iter_park.argtypes = [c_void_p]

# iter_destroy
libwh.wh_iter_destroy.argtypes = [c_void_p]
# }}} libwh

# class {{{
class Wh:
    def __init__(self, maxklen=256, maxvlen=8192):
        self.whptr = libwh.wh_create()
        self.kbufsz = maxklen
        self.vbufsz = maxvlen

    # user must call explicitly
    def destroy(self):
        libwh.wh_destroy(self.whptr)

    def ref(self):
        return WhRef(self.whptr, self.kbufsz, self.vbufsz)

class WhRef:
    def __init__(self, whptr, kbufsz, vbufsz):
        self.refptr = libwh.wh_ref(whptr)
        self.kbufsz = kbufsz
        self.vbufsz = vbufsz
        self.vbuf = create_string_buffer(self.vbufsz)

    # user must call explicitly
    def unref(self):
        libwh.wh_unref(self.refptr)

    def iter(self):
        return WhIter(self.refptr, self.kbufsz, self.vbufsz)

    # key: python string; value: any (hierarchical) python object
    def put(self, key, value):
        binkey = key.encode()
        binvalue = msgpack.packb(value)
        return libwh.wh_put(self.refptr, binkey, c_uint(len(binkey)), binvalue, c_uint(len(binvalue)))

    # return the value as a python object
    def get(self, key):
        binkey = key.encode()
        vlen = c_uint()
        ret = libwh.wh_get(self.refptr, binkey, len(binkey), self.vbuf, self.vbufsz, byref(vlen))
        if ret and vlen.value <= self.vbufsz:
            return msgpack.unpackb(self.vbuf.value)
        else:
            return None

    def delete(self, key):
        binkey = key.encode()
        return libwh.wh_del(self.refptr, binkey, c_uint(len(binkey)))

    def probe(self, key):
        binkey = key.encode()
        return libwh.wh_probe(self.refptr, binkey, c_uint(len(binkey)))

class WhIter:
    def __init__(self, refptr, kbufsz, vbufsz):
        self.iptr = libwh.wh_iter_create(refptr)
        self.kbufsz = kbufsz
        self.vbufsz = vbufsz
        self.kbuf = create_string_buffer(kbufsz)
        self.vbuf = create_string_buffer(vbufsz)

    # user must call explicitly
    def destroy(self):
        libwh.wh_iter_destroy(self.iptr)

    def seek(self, key):
        if key is None:
            libwh.wh_iter_seek(self.iptr, None, c_uint(0))
        else:
            binkey = key.encode()
            libwh.wh_iter_seek(self.iptr, binkey, c_uint(len(binkey)))

    def valid(self):
        return libwh.wh_iter_valid(self.iptr)

    def skip1(self):
        libwh.wh_iter_skip1(self.iptr)

    def skip(self, nr):
        libwh.wh_iter_skip(self.iptr, c_uint(nr))

    # return (key, value) pair or None
    def peek(self):
        klen = c_uint()
        vlen = c_uint()
        ret = libwh.wh_iter_peek(self.iptr, self.kbuf, self.kbufsz, byref(klen), self.vbuf, self.vbufsz, byref(vlen))
        if ret and klen.value <= self.kbufsz and vlen.value <= self.vbufsz:
            self.kbuf[klen.value] = b'\x00'
            return (self.kbuf.value.decode(), klen.value, msgpack.unpackb(self.vbuf.value), vlen.value)
        else:
            return None

# }}} class

# examples
wh1 = Wh(32, 1024)
ref1 = wh1.ref()  # take a ref for kv operations

ref1.put("Hello", "pywh")
ref1.put("key1", "value1")
ref1.put("key2", "value2")
ref1.put("key3", {"xxx":"valuex", "yyy":"valuey"})
ref1.delete("key2")

rget = ref1.get("Hello")
print(rget)

# don't use ref when iterating
iter1 = ref1.iter()
iter1.seek(None)
while iter1.valid():
    r = iter1.peek()
    print(r)
    iter1.skip1()

iter1.destroy() # must destroy all iters before unref
ref1.unref() # must unref all refs before close()
wh1.destroy()

# vim:fdm=marker
