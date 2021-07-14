/*
 * Copyright (c) 2021  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#define _GNU_SOURCE
#include <stdio.h>

#include "lib.h"
#include "kv.h"
#include "wh.h"

  int
main(int argc, char ** argv)
{
  (void)argc;
  (void)argv;
  struct wormhole * const wh = wh_create();
  struct wormref * const ref = wh_ref(wh);

  bool r;

  r = wh_put(ref, "wormhole", 8, "easy", 4);
  printf("wh_put wormhole easy %c\n", r?'T':'F');

  r = wh_put(ref, "time_travel", 11, "impossible", 10);
  printf("wh_put time_travel impossible %c\n", r?'T':'F');

  r = wh_del(ref, "time_travel", 11);
  printf("wh_del time_travel %c\n", r?'T':'F');

  r = wh_probe(ref, "time_travel", 11);
  printf("wh_probe time_travel %c\n", r?'T':'F');

  u32 klen_out = 0;
  char kbuf_out[8] = {};
  u32 vlen_out = 0;
  char vbuf_out[8] = {};
  r = wh_get(ref, "wormhole", 8, vbuf_out, 8, &vlen_out);
  printf("wh_get wormhole %c %u %.*s\n", r?'T':'F', vlen_out, vlen_out, vbuf_out);

  // in a concurrent environment, the kvmap_api_wormhole need park&resume when a thread is about to go idle
  // don't need park&resume if you're using the default kvmap_api_whsafe in whwh.c!
  wh_park(ref);
  usleep(10);
  wh_resume(ref);

  // prepare a few keys for range ops
  wh_put(ref, "00", 2, "0_value", 7);
  wh_put(ref, "11", 2, "1_value", 7);
  wh_put(ref, "22", 2, "2_value", 7);

  struct wormhole_iter * const iter = wh_iter_create(ref);

  wh_iter_seek(iter, NULL, 0); // seek to the head
  printf("wh_iter_seek \"\"\n");
  while (wh_iter_valid(iter)) {
    r = wh_iter_peek(iter, kbuf_out, 8, &klen_out, vbuf_out, 8, &vlen_out);
    if (r) {
      printf("wh_iter_peek klen=%u key=%.*s vlen=%u value=%.*s\n",
          klen_out, klen_out, kbuf_out, vlen_out, vlen_out, vbuf_out);
    } else {
      printf("ERROR!\n");
    }
    wh_iter_skip1(iter);
  }

  // call iter_park if you will go idle but want to use the iter later
  // don't need to call iter_park if you're actively using iter
  wh_iter_park(iter);
  usleep(10);

  wh_iter_seek(iter, "0", 1);
  printf("wh_iter_seek \"0\"\n");
  // this time we don't want to copy the value
  r = wh_iter_peek(iter, kbuf_out, 8, &klen_out, NULL, 0, NULL);
  if (r){
    printf("wh_iter_peek klen=%u key=%.*s\n", klen_out, klen_out, kbuf_out);
  } else {
    printf("ERROR: iter_peek failed\n");
  }

  wh_iter_destroy(iter);
  // there must be no active iter when calling unref()
  wh_unref(ref);

  // unsafe operations: should have released all references
  wh_clean(wh); // just for demonstration
  wh_destroy(wh); // destroy also calls clean interally
  return 0;
}
