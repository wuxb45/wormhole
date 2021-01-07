/*
 * Copyright (c) 2018  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "lib.h"
#include "kv.h"
#include "wh.h"

char * __buf = NULL;
size_t __size = 0;
struct kv * __kv = NULL;
struct kv * __out = NULL;
struct kref __kref;

  static void
scan_trace(FILE * const input)
{
  rewind(input);
  u64 count = 0;
  __buf = NULL;
  while (getline(&__buf, &__size, input) > 0) count++;
  printf("#lines %lu\n", count);
  free(__buf);
  __kv = malloc(__size + 64);
  __buf = (char *)__kv->kv;
  __out = malloc(__size + 64);
}

  static void
wh_set(struct wormref * const ref, FILE * input)
{
  rewind(input);
  u64 count = 0;
  while (fgets(__buf, __size, input)) {
    __kv->klen = strlen(__buf);
    __kv->vlen = 0;
    kv_update_hash(__kv);
    wormhole_set(ref, __kv);
    count++;
  }
  printf("insert/update %lu (== #lines)\n", count);
}

  static void
wh_get(struct wormref * const ref, FILE * input)
{
  rewind(input);
  u64 hit = 0;
  while (fgets(__buf, __size, input)) {
    kref_ref_hash32(&__kref, (const u8 *)__buf, strlen(__buf));
    if (wormhole_get(ref, &__kref, __out))
      hit++;
  }
  printf("get hit %lu (== #lines)\n", hit);
}

  static void
wh_probe(struct wormref * const ref, FILE * input)
{
  rewind(input);
  u64 hit = 0;
  while (fgets(__buf, __size, input)) {
    kref_ref_hash32(&__kref, (const u8 *)__buf, strlen(__buf));
    if (wormhole_probe(ref, &__kref))
      hit++;
  }
  printf("probe hit %lu (== #lines)\n", hit);
}

  static void
wh_iter(struct wormref * const ref, FILE * input)
{
  rewind(input);
  struct wormhole_iter * const iter = wormhole_iter_create(ref);
  struct kv * const tmp1 = malloc(1024);
  u64 count = 0;
  while (wormhole_iter_next(iter, tmp1))
    count++;
  printf("unique keys %lu (<= #lines)\n", count);

  count = 0;
  rewind(input);
  do {
    if (fgets(__buf, __size, input) == NULL)
      break;
    kref_ref_hash32(&__kref, (const u8 *)__buf, strlen(__buf));
    wormhole_iter_seek(iter, &__kref);
    for (u64 i = 0; i < 100; i++) {
      if (wormhole_iter_next(iter, tmp1))
        count++;
      else
        break;
    }
    for (u64 i = 0; i < 99; i++)
      fgets(__buf, __size, input);
  } while (true);
  printf("seek-scan keys %lu (should be very close to #lines)\n", count);
  // iter may hold a leaf lock. Destroy it.
  wormhole_iter_destroy(iter);
  free(tmp1);
}

  static void
wh_del(struct wormref * const ref, FILE * input)
{
  rewind(input);
  u64 hit = 0;
  while (fgets(__buf, __size, input)) {
    kref_ref_hash32(&__kref, (const u8 *)__buf, strlen(__buf));
    if (wormhole_del(ref, &__kref))
      hit++;
  }
  printf("del hit %lu (== unique keys)\n", hit);
}

  int
main(int argc, char ** argv)
{
  if (argc < 2) {
    printf("usage: %s <keys-file (in plain text)>\n", argv[0]);
    exit(0);
  }
  FILE * const input = fopen(argv[1], "r");
  if (input == NULL) {
    printf("fopen() failed\n");
    exit(0);
  }
  scan_trace(input);
  struct wormhole * const wh = wormhole_create(NULL);
  struct wormref * const ref = wormhole_ref(wh);
  wh_set(ref, input);
  wh_get(ref, input);
  wh_probe(ref, input);
  wh_iter(ref, input);
  wh_del(ref, input);
  wormhole_unref(ref);
  wormhole_destroy(wh);
  free(__kv);
  free(__out);
  fclose(input);
  return 0;
}
