#ifndef MINE_AVX
#define MINE_AVX

#include "mine.h"

#define MINE_SIMD(EXTENSION,N_LANES,DATA_TYPE)                                                                             \
__attribute__((unused))                                                                                                    \
static u32_t mine_ ## EXTENSION(const mine_job_t *job,u32_t zero_bits,u64_t first,u64_t count,u64_t *hits,u32_t max_hits)  \
{                                                                                                                          \
  const u32_t mask = mine_mask(zero_bits);                                                                                 \
  const u32_t nonce_end = job->nonce_pos + job->nonce_len;                                                                 \
  const u32_t last = nonce_end / 4u - 1u;                                                                                  \
  DATA_TYPE data[2][16],state[5],hash[5];                                                                                  \
  u32_t n_hits = 0u;                                                                                                       \
                                                                                                                           \
  assert(count % N_LANES == 0u);                                                                                           \
  for(u32_t lane = 0u;lane < N_LANES;lane++)                                                                               \
  {                                                                                                                        \
    u32_t block[16];                                                                                                       \
                                                                                                                           \
    memcpy(block,job->block[0],sizeof(block));                                                                             \
    mine_block_set_nonce(job,block,first + lane);                                                                          \
    for(int i = 0;i < 16;i++)                                                                                              \
    {                                                                                                                      \
      data[0][i][lane] = (int)block[i];                                                                                    \
      data[1][i][lane] = (int)job->block[1][i];                                                                            \
    }                                                                                                                      \
    for(int i = 0;i < 5;i++)                                                                                               \
      state[i][lane] = (int)job->state[i];                                                                                 \
  }                                                                                                                        \
  for(u64_t n = first;n < first + count;n += N_LANES)                                                                      \
  {                                                                                                                        \
    for(int i = 0;i < 5;i++)                                                                                               \
      hash[i] = state[i];                                                                                                  \
    sha1_update_ ## EXTENSION(data[0],hash);                                                                               \
    if(job->n_blocks == 2u)                                                                                                \
      sha1_update_ ## EXTENSION(data[1],hash);                                                                             \
    for(u32_t lane = 0u;lane < N_LANES;lane++)                                                                             \
    {                                                                                                                      \
      u32_t word = (u32_t)data[0][last][lane] + N_LANES;                                                                   \
                                                                                                                           \
      if(((u32_t)hash[4][lane] & mask) == 0u)                                                                              \
      {                                                                                                                    \
        if(n_hits < max_hits)                                                                                              \
          hits[n_hits] = n + lane;                                                                                         \
        n_hits++;                                                                                                          \
      }                                                                                                                    \
      if((word & 0xFFu) <= (u32_t)'9')                                                                                     \
        data[0][last][lane] = (int)word;                                                                                   \
      else                                                                                                                 \
      {                                                                                                                    \
        data[0][last][lane] = (int)(word - 10u);                                                                           \
        for(u32_t pos = nonce_end - 1u;pos-- > job->nonce_pos;)                                                            \
        {                                                                                                                  \
          u32_t shift = 8u * (3u - pos % 4u);                                                                              \
                                                                                                                           \
          word = (u32_t)data[0][pos / 4u][lane];                                                                           \
          if(((word >> shift) & 0xFFu) != (u32_t)'9')                                                                      \
          {                                                                                                                \
            data[0][pos / 4u][lane] = (int)(word + (1u << shift));                                                         \
            break;                                                                                                         \
          }                                                                                                                \
          data[0][pos / 4u][lane] = (int)(word - (9u << shift));                                                           \
        }                                                                                                                  \
      }                                                                                                                    \
    }                                                                                                                      \
  }                                                                                                                        \
  return n_hits;                                                                                                           \
}

#if defined(__AVX__)
MINE_SIMD(avx,4u,v4si)
#endif

#if defined(__AVX2__)
MINE_SIMD(avx2,8u,v8si)
#endif

#endif
