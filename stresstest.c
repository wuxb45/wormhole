/*
 * Copyright (c) 2018-2019  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <immintrin.h>
#include <stdatomic.h>
#include <time.h>
#include "wh.h"

u64 nr_words = 0;
char ** words = NULL;
atomic_uint_least64_t seqno = 0;
u64 nth = 0;
struct kv ** samples = NULL;
u64 nkeys = 0;
atomic_uint_least64_t tot = 0;
u64 endtime = 0;

  static void *
kv_load_worker(struct wormhole * const wh)
{
  srandom_u64(rdtsc() * rdtsc());
  struct wormref * const ref = wormhole_ref(wh);
  const u64 seq = atomic_fetch_add(&seqno, 1);
  const u64 n0 = nkeys / nth * seq;
  const u64 nz = (seq == (nth - 1)) ? nkeys : (nkeys / nth * (seq + 1));
  printf("load worker %lu %lu\n", n0, nz);

  char * buf = malloc(8192);
  char * ss[6];
  for (u64 i = n0; i < nz; i++) {
    for (u64 j = 0; j < 6; j++)
      ss[j] = words[random() % nr_words];
    sprintf(buf, "%s %s %s %s %s %s!", ss[0], ss[1], ss[2], ss[3], ss[4], ss[5]);
    samples[i] = kv_create_str(buf, "");
    wormhole_set(ref, samples[i]);
  }
  wormhole_unref(ref);
  return NULL;
}

  static void *
kv_probe_worker(struct wormhole * const wh)
{
  srandom_u64(rdtsc() * rdtsc());
  struct wormref * ref = wormhole_ref(wh);
  struct kv * next = samples[random_u64() % nkeys];
  u64 rnext = random_u64() % nkeys;
  struct kv * const getbuf = malloc(1000);
  struct sbuf * const sbuf = malloc(1000);
  struct wormhole_iter * iter;
#define BATCHSIZE ((1000))
  do {
    for (u64 i = 0; i < BATCHSIZE; i++) {
      // reading kv samples leads to unnecessary cache misses
      // use prefetch to minimize overhead on workload generation
      struct kv * const key = next;
      next = samples[rnext];
      __builtin_prefetch(next, 0, 0);
      __builtin_prefetch(((u8 *)next) + 64, 0, 0);
      rnext = random_u64() % nkeys;
      __builtin_prefetch(&(samples[rnext]));

      // do probe
      // customize your benchmark: do a mix of wh operations with switch-cases
      const u64 r = rdtsc() % 12;
      //ctrs[r]++;
      switch (r) {
      case 0:
        (void)wormhole_probe(ref, key);
        break;
      case 1:
        (void)wormhole_get(ref, key, getbuf);
        break;
      case 2:
        (void)wormhole_getv(ref, key, sbuf);
        break;
      case 3:
        (void)wormhole_getu64(ref, key);
        break;
      case 4:
        iter = wormhole_iter_create(ref);
        wormhole_iter_seek(iter, key);
        (void)wormhole_iter_next(iter, getbuf);
        wormhole_iter_destroy(iter);
        break;
      case 5:
        (void)wormhole_unref(ref);
        ref = wormhole_ref(wh);
        break;
      case 6: case 7:
        (void)wormhole_del(ref, key);
        break;
      case 8: case 9: case 10: case 11:
        (void)wormhole_set(ref, key);
        break;
      default:
        break;
      }
    }
    tot += BATCHSIZE;
  } while (time_nsec() < endtime);
  wormhole_unref(ref);
  free(getbuf);
  free(sbuf);
  return NULL;
}


  int
main(int argc, char ** argv)
{
  if (argc < 4) {
    printf("usage: <words-file> <#keys> <#threads> [<rounds>]\n");
    printf("  Get words.txt: wget https://github.com/dwyl/english-words/raw/master/words.txt\n");
    printf("  Example: %s words.txt 1000000 4\n", argv[0]);
    printf("  Better to use only one numa node with numactl -N 0\n");
    printf("  Better to run X thread on X cores\n");
    return 0;
  }

  words = malloc(sizeof(char *) * 1000000); // or `wc -l words.txt`
  nr_words = 0;
  char * buf = malloc(8192);
  size_t bufsize = 8192;
  FILE * const fwords = fopen(argv[1], "r");
  if (fwords == NULL) {
    printf("open words file failed\n");
    return 0;
  }

  // read all words to words
  while ((nr_words < 1000000) && (getline(&buf, &bufsize, fwords) > 0)) {
    buf[strlen(buf)-1] = '\0';
    words[nr_words] = strdup(buf);
    nr_words++;
  }
  free(buf);
  fclose(fwords);

  // generate keys
  nkeys = strtoull(argv[2], NULL, 10);
  samples = malloc(sizeof(struct kv *) * nkeys);

  // gen keys and load (4)
  struct wormhole * const wh = wormhole_create(NULL);
  nth = 4;
  const double dtl = thread_fork_join(nth, (void *)kv_load_worker, false, (void *)wh);
  printf("gen and load x4 %.2lf mops\n", ((double)nkeys) / dtl * 1e-6);

  // free words & buf
  for (u64 i = 0; i < nr_words; i++)
    free(words[i]);
  free(words);

  nth = strtoull(argv[3], NULL, 10);
  printf("stresstest with %lu threads.\n", nth);
  u64 todo = (argc >= 5) ? strtoull(argv[4], NULL, 10) : ~0lu;
  while (todo--) {
    tot = 0;
    endtime = time_nsec() + 2e9;
    const double dt = thread_fork_join(nth, (void *)kv_probe_worker, false, (void *)wh);
    const double mops = ((double)tot) / dt * 1e-6;
    time_t now;
    time(&now);
    struct tm nowtm;
    localtime_r(&now, &nowtm);
    char timestamp[64] = {};
    strftime(timestamp, 64, "%F %T %Z (%z)", &nowtm);
    printf("%s stresstest x%lu %.2lf mops\n", timestamp, nth, mops);
  }

  // final clean up for valgrind
  for (u64 i = 0; i < nkeys; i++)
    free(samples[i]);
  free(samples);
  wormhole_destroy(wh);
  return 0;
}
