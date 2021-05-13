/*
 * Copyright (c) 2016--2021  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#define _GNU_SOURCE

#include "lib.h"
#include "kv.h"
#include "wh.h"

#define NKEYS 10000000
  int
main(int argc, char ** argv)
{
  const u64 nkeys = argc > 1 ? a2u64(argv[1]) : NKEYS;
  // prepare u64 keys
  u64 * const keys = malloc(sizeof(u64) * nkeys);
  for (u64 i = 0; i < nkeys; i++)
    keys[i] = random_u64();

  const struct kvmap_mm mm_nnn = {kvmap_mm_in_noop, kvmap_mm_out_noop, kvmap_mm_free_noop, NULL};
  struct wormhole * const wh = wormhole_u64_create(&mm_nnn);
  struct wormref * const ref = wormhole_ref(wh);
  const double t0 = time_sec();
  for (u64 i = 0; i < nkeys; i++)
    wormhole_u64_set(ref, keys[i], (void *)~keys[i]); // (void *) is just a u64 value
  const double t1 = time_sec();

  wormhole_verify(wh);

  const double t2 = time_sec();
  debug_perf_switch();
  u64 err = 0;
  for (u64 i = 0; i < nkeys; i++) {
    u64 r = (u64)wormhole_u64_get(ref, keys[i], NULL);
    if (~r != keys[i]) {
      err++;
      printf("key not found at %lu key=%lx\n", i, keys[i]);
      (void)wormhole_u64_get(ref, keys[i], NULL);// for debugging
    }
  }
  debug_perf_switch();
  const double t3 = time_sec();

  printf("set dt %.3lf mops %.3lf get dt %.3lf mops %.3lf err %lu\n",
      t1-t0, (double)nkeys / (t1-t0) * 1e-6, t3-t2, (double)nkeys / (t3-t2) * 1e-6, err);

  wormhole_unref(ref);
  wormhole_u64_destroy(wh);
  free(keys);
  return 0;
}
