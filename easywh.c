/*
 * Copyright (c) 2021  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "lib.h"
#include "kv.h"
#include "wh.h"
#include "easywh.h"

// Users often don't enjoy dealing with struct kv/kref and just want to use plain buffers.
// No problem!
// This example library shows you how to use Wormhole efficiently in the most intuitive way.

// Use the worry-free api
static const struct kvmap_api * const wh_api = &kvmap_api_whsafe;

// You can change the wh_api to kvmap_api_wormhole with a one-line replacement
// The standard Wormhole api can give you ~5% boost; read README for thread-safety tips
//static const struct kvmap_api * const wh_api = &kvmap_api_wormhole;

  struct wormhole *
wh_create(void)
{
  // kvmap_mm_ndf (kv.h) will let the caller allocate the kv when inserting
  // This can avoid a memcpy if the caller does not have the data in a struct kv
  return wormhole_create(&kvmap_mm_ndf);
}

  struct wormref *
wh_ref(struct wormhole * const wh)
{
  return wh_api->ref(wh);
}

  void
wh_unref(struct wormref * const ref)
{
  (void)wh_api->unref(ref);
}

  void
wh_park(struct wormref * const ref)
{
  if (wh_api->park)
    wh_api->park(ref);
}

  void
wh_resume(struct wormref * const ref)
{
  if (wh_api->resume)
    wh_api->resume(ref);
}

  void
wh_clean(struct wormhole * const map)
{
  wh_api->clean(map);
}

  void
wh_destroy(struct wormhole * const map)
{
  wh_api->destroy(map);
}

// Do set/put with explicit kv buffers
  bool
wh_set(struct wormref * const ref, const void * const kbuf, const u32 klen,
    const void * const vbuf, const u32 vlen)
{
  struct kv * const newkv = kv_create(kbuf, klen, vbuf, vlen);
  // must use with kvmap_mm_ndf (see below)
  // the newkv will be saved in the Wormhole and freed by Wormhole when upon deletion
  return wh_api->set(ref, newkv);
}

// delete a key
  bool
wh_del(struct wormref * const ref, const void * const kbuf, const u32 klen)
{
  struct kref kref;
  kref_ref_hash32(&kref, kbuf, klen);
  return wh_api->del(ref, &kref);
}

// test if the key exist in Wormhole
  bool
wh_probe(struct wormref * const ref, const void * const kbuf, const u32 klen)
{
  struct kref kref;
  kref_ref_hash32(&kref, kbuf, klen);
  return wh_api->probe(ref, &kref);
}

// for wh_get()
struct wh_inp_info { void * vbuf_out; u32 * vlen_out; };

// a kv_inp_func; use this to retrieve the KV's data without unnecesary memory copying
  static void
inp_copy_value_cb(struct kv * const curr, void * const priv)
{
  if (curr) { // found
    struct wh_inp_info * const info = (typeof(info))priv;
    // copy the value data out
    memcpy(info->vbuf_out, kv_vptr_c(curr), curr->vlen);
    // copy the vlen out
    *info->vlen_out = curr->vlen;
  }
}

// returns a boolean value indicating whether the key is found.
// the value's data will be written to *vlen_out and vbuf_out if the key is found
// We assume vbuf_out is large enough to hold the output value
  bool
wh_get(struct wormref * const ref, const void * const kbuf, const u32 klen,
    void * const vbuf_out, u32 * const vlen_out)
{
  struct kref kref;
  kref_ref_hash32(&kref, kbuf, klen);
  struct wh_inp_info info = {vbuf_out, vlen_out};
  // use the inplace read function to get the value if it exists
  return wh_api->inpr(ref, &kref, inp_copy_value_cb, &info);
}

  bool
wh_inpr(struct wormref * const ref, const void * const kbuf, const u32 klen,
    kv_inp_func uf, void * const priv)
{
  struct kref kref;
  kref_ref_hash32(&kref, kbuf, klen);
  return wh_api->inpr(ref, &kref, uf, priv);
}

// inplace update KV's value with a user-defined hook function
// the update should only modify the data in the value; It should not change the value size
  bool
wh_inpw(struct wormref * const ref, const void * const kbuf, const u32 klen,
    kv_inp_func uf, void * const priv)
{
  struct kref kref;
  kref_ref_hash32(&kref, kbuf, klen);
  return wh_api->inpw(ref, &kref, uf, priv);
}

// merge existing KV with updates with a user-defined hook function
  bool
wh_merge(struct wormref * const ref, const void * const kbuf, const u32 klen,
    kv_merge_func uf, void * const priv)
{
  struct kref kref;
  kref_ref_hash32(&kref, kbuf, klen);
  return wh_api->merge(ref, &kref, uf, priv);
}

// remove a range of KVs from start (inclusive) to end (exclusive); [start, end)
  u64
wh_delr(struct wormref * const ref, const void * const kbuf_start, const u32 klen_start,
    const void * const kbuf_end, const u32 klen_end)
{
  struct kref kref_start, kref_end;
  kref_ref_hash32(&kref_start, kbuf_start, klen_start);
  kref_ref_hash32(&kref_end, kbuf_end, klen_end);
  return wh_api->delr(ref, &kref_start, &kref_end);
}

  struct wormhole_iter *
wh_iter_create(struct wormref * const ref)
{
  return wh_api->iter_create(ref);
}

  void
wh_iter_seek(struct wormhole_iter * const iter, const void * const kbuf, const u32 klen)
{
  struct kref kref;
  kref_ref_hash32(&kref, kbuf, klen);
  wh_api->iter_seek(iter, &kref);
}

  bool
wh_iter_valid(struct wormhole_iter * const iter)
{
  return wh_api->iter_valid(iter);
}

// for wh_iter_peek()
// the out ptrs must be provided in pairs; use a pair of NULLs to ignore the key or value
struct wh_iter_inp_info { void * kbuf_out; u32 * klen_out; void * vbuf_out; u32 * vlen_out; };

// a kv_inp_func; use this to retrieve the KV's data without unnecesary memory copying
  static void
inp_copy_kv_cb(struct kv * const curr, void * const priv)
{
  if (curr) { // found
    struct wh_iter_inp_info * const info = (typeof(info))priv;

    // copy the key
    if (info->kbuf_out) { // it assumes klen_out is also not NULL
      // copy the key data out
      memcpy(info->kbuf_out, kv_kptr_c(curr), curr->klen);
      // copy the klen out
      *info->klen_out = curr->klen;
    }

    // copy the value
    if (info->vbuf_out) { // it assumes vlen_out is also not NULL
      // copy the value data out
      memcpy(info->vbuf_out, kv_vptr_c(curr), curr->vlen);
      // copy the vlen out
      *info->vlen_out = curr->vlen;
    }
  }
}

// seek is similar to get
  bool
wh_iter_peek(struct wormhole_iter * const iter,
    void * const kbuf_out, u32 * const klen_out,
    void * const vbuf_out, u32 * const vlen_out)
{
  struct wh_iter_inp_info info = {kbuf_out, klen_out, vbuf_out, vlen_out};
  return wh_api->iter_inp(iter, inp_copy_kv_cb, &info);
}

  void
wh_iter_skip(struct wormhole_iter * const iter, const u32 nr)
{
  wh_api->iter_skip(iter, nr);
}

  bool
wh_iter_inp(struct wormhole_iter * const iter, kv_inp_func uf, void * const priv)
{
  return wh_api->iter_inp(iter, uf, priv);
}

  void
wh_iter_park(struct wormhole_iter * const iter)
{
  wh_api->iter_park(iter);
}

  void
wh_iter_destroy(struct wormhole_iter * const iter)
{
  wh_api->iter_destroy(iter);
}
