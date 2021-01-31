/*
 * Copyright (c) 2016--2020  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include "lib.h"
#include "kv.h"
#include "wh.h"

  extern struct wormhole *
wh_create(void);

  extern struct wormref *
wh_ref(struct wormhole * const wh);

  extern void
wh_unref(struct wormref * const ref);

  extern void
wh_park(struct wormref * const ref);

  extern void
wh_resume(struct wormref * const ref);

  extern void
wh_clean(struct wormhole * const map);

  extern void
wh_destroy(struct wormhole * const map);

  extern bool
wh_set(struct wormref * const ref, const void * const kbuf, const u32 klen,
    const void * const vbuf, const u32 vlen);

  extern bool
wh_del(struct wormref * const ref, const void * const kbuf, const u32 klen);

  extern bool
wh_probe(struct wormref * const ref, const void * const kbuf, const u32 klen);

  extern bool
wh_get(struct wormref * const ref, const void * const kbuf, const u32 klen,
    void * const vbuf_out, u32 * const vlen_out);

  extern bool
wh_inpr(struct wormref * const ref, const void * const kbuf, const u32 klen,
    kv_inp_func uf, void * const priv);

  extern bool
wh_inpw(struct wormref * const ref, const void * const kbuf, const u32 klen,
    kv_inp_func uf, void * const priv);

  extern bool
wh_merge(struct wormref * const ref, const void * const kbuf, const u32 klen,
    kv_merge_func uf, void * const priv);

  extern u64
wh_delr(struct wormref * const ref, const void * const kbuf_start, const u32 klen_start,
    const void * const kbuf_end, const u32 klen_end);

  extern struct wormhole_iter *
wh_iter_create(struct wormref * const ref);

  extern void
wh_iter_seek(struct wormhole_iter * const iter, const void * const kbuf, const u32 klen);

  extern bool
wh_iter_valid(struct wormhole_iter * const iter);

  extern bool
wh_iter_peek(struct wormhole_iter * const iter,
    void * const kbuf_out, u32 * const klen_out,
    void * const vbuf_out, u32 * const vlen_out);

  extern void
wh_iter_skip(struct wormhole_iter * const iter, const u32 nr);

  extern bool
wh_iter_inp(struct wormhole_iter * const iter, kv_inp_func uf, void * const priv);

  extern void
wh_iter_park(struct wormhole_iter * const iter);

  extern void
wh_iter_destroy(struct wormhole_iter * const iter);

#ifdef __cplusplus
}
#endif
// vim:fdm=marker
