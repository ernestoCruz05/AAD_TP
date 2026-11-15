#ifndef MINE_SCALAR
#define MINE_SCALAR

#include "mine.h"

__attribute__((unused))
static u32_t mine_scalar(const mine_job_t *job,u32_t zero_bits,u64_t first,u64_t count,u64_t *hits,u32_t max_hits)
{
  const u32_t mask = mine_mask(zero_bits);
  const u32_t nonce_end = job->nonce_pos + job->nonce_len;
  const u32_t last = nonce_end / 4u - 1u;
  u32_t block[2][16],hash[5];
  u32_t n_hits = 0u;

  memcpy(block,job->block,sizeof(block));
  mine_block_set_nonce(job,block[0],first);
  for(u64_t n = first;n < first + count;n++)
  {
    memcpy(hash,job->state,sizeof(hash));
    sha1_update(block[0],hash);
    if(job->n_blocks == 2u)
      sha1_update(block[1],hash);
    if((hash[4] & mask) == 0u)
    {
      if(n_hits < max_hits)
        hits[n_hits] = n;
      n_hits++;
    }
    if((block[0][last] & 0xFFu) != (u32_t)'9')
      block[0][last]++;
    else
      for(u32_t pos = nonce_end;pos-- > job->nonce_pos;)
      {
        u32_t shift = 8u * (3u - pos % 4u);

        if(((block[0][pos / 4u] >> shift) & 0xFFu) != (u32_t)'9')
        {
          block[0][pos / 4u] += 1u << shift;
          break;
        }
        block[0][pos / 4u] -= 9u << shift;
      }
  }
  return n_hits;
}

#endif
