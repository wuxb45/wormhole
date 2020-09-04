/*
 * Copyright (c) 2016--2020  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#pragma once

// C types only

#include <stdatomic.h>
#if defined(__x86_64__)
#include <x86intrin.h>
#elif defined(__aarch64__)
#include <arm_acle.h>
#include <arm_neon.h>
#endif

/* C11 atomic types */
typedef atomic_bool             abool;

typedef atomic_uint_least8_t    au8;
typedef atomic_uint_least16_t   au16;
typedef atomic_uint_least32_t   au32;
typedef atomic_uint_least64_t   au64;

typedef atomic_int_least8_t     as8;
typedef atomic_int_least16_t    as16;
typedef atomic_int_least32_t    as32;
typedef atomic_int_least64_t    as64;

// shorten long names
#define MO_RELAXED memory_order_relaxed
#define MO_CONSUME memory_order_consume
#define MO_ACQUIRE memory_order_acquire
#define MO_RELEASE memory_order_release
#define MO_ACQ_REL memory_order_acq_rel
#define MO_SEQ_CST memory_order_seq_cst

#if defined(__x86_64__)
typedef __m128i m128;
#elif defined(__aarch64__)
typedef uint8x16_t m128;
#endif
