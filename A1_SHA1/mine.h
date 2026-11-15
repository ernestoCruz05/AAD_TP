#ifndef MINE
#define MINE

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aad_data_types.h"
#include "aad_sha1_cpu.h"

#define MINE_DIGITS         0u
#define MINE_LSB            1u
#define MINE_NONCE_DIGITS  16u
#define MINE_MAX_FILE_SIZE (1ul << 30)

typedef struct
{
  u08_t *data;
  u64_t file_size;
  u64_t data_size;
  u64_t nonce_pos;
  u32_t nonce_len;
  u32_t kind;
  u64_t crc_pos;
  u64_t crc_from;
}
mine_file_t;

typedef struct
{
  u32_t state[5];
  u32_t n_blocks;
  u32_t block[2][16];
  u32_t kind;
  u32_t nonce_pos;
  u32_t nonce_len;
  u32_t has_crc;
  u32_t crc_state;
}
mine_job_t;


__attribute__((unused))
static u32_t mine_mask(u32_t zero_bits)
{
  return (zero_bits >= 32u) ? 0xFFFFFFFFu : (1u << zero_bits) - 1u;
}

__attribute__((unused))
static void mine_load_block(const u08_t *bytes,u32_t block[16])
{
  for(size_t i = 0u;i < 16u;i++)
    block[i] =((u32_t)bytes[4 * i] << 24) | ((u32_t)bytes[4 * i + 1] << 16) | ((u32_t)bytes[4 * i + 2] << 8) | (u32_t)bytes[4 * i + 3];
}

__attribute__((unused))
static void mine_sha1(const u08_t *data,u64_t data_size,u32_t hash[5])
{
  u32_t block[16];

  hash[0] = initial_H0;
  hash[1] = initial_H1;
  hash[2] = initial_H2;
  hash[3] = initial_H3;
  hash[4] = initial_H4;
  for(u64_t i = 0u;i < data_size;i += 64u)
  {
    mine_load_block(&data[i],block);
    sha1_update(block,hash);
  }
}

__attribute__((unused))
static u64_t mine_padded_size(u64_t file_size)
{
  return (file_size + 9u + 63u) / 64u * 64u;
}

__attribute__((unused))
static void mine_pad(mine_file_t *f)
{
  u64_t i = f->file_size;
  u64_t n_bits = 8u * f->file_size;

  f->data[i++] = 0x80;
  while(i % 64u != 56u)
    f->data[i++] = 0x00;
  for(int shift = 56;shift >= 0;shift -= 8)
    f->data[i++] = (u08_t)(n_bits >> shift);
  assert(i == f->data_size);
}

__attribute__((unused))
static void mine_set_nonce(mine_file_t *f,u64_t n)
{
  for(u32_t i = f->nonce_len;i-- > 0u;n /= 10u)
    f->data[f->nonce_pos + i] = (u08_t)('0' + n % 10u);
}

__attribute__((unused))
static void mine_block_set_nonce(const mine_job_t *job,u32_t block[16],u64_t n)
{
  for(u32_t pos = job->nonce_pos + job->nonce_len;pos-- > job->nonce_pos;n /= 10u)
  {
    u32_t shift = 8u * (3u - pos % 4u);

    block[pos / 4u] = (block[pos / 4u] & ~(0xFFu << shift)) | ((u32_t)('0' + n % 10u) << shift);
  }
}

__attribute__((unused))
static void mine_make_job(const mine_file_t *f,mine_job_t *job)
{
  u64_t first = f->nonce_pos / 64u;
  u64_t n_blocks = f->data_size / 64u - first;

  assert((f->nonce_pos + f->nonce_len) % 4u == 0u);
  assert((f->nonce_pos + f->nonce_len - 1u) / 64u == first);
  assert(n_blocks == 1u || n_blocks == 2u);
  memset(job,0,sizeof(*job));
  mine_sha1(f->data,64u * first,job->state);
  job->n_blocks = (u32_t)n_blocks;
  for(u64_t i = 0u;i < n_blocks;i++)
    mine_load_block(&f->data[64u * (first + i)],job->block[i]);
  job->kind = f->kind;
  job->nonce_pos = (u32_t)(f->nonce_pos % 64u);
  job->nonce_len = f->nonce_len;
}

__attribute__((unused))
static void mine_job_hash(const mine_job_t *job,u64_t n,u32_t hash[5])
{
  u32_t block[2][16];

  memcpy(block,job->block,sizeof(block));
  memcpy(hash,job->state,sizeof(job->state));
  mine_block_set_nonce(job,block[0],n);
  for(u32_t i = 0u;i < job->n_blocks;i++)
    sha1_update(block[i],hash);
}

__attribute__((unused))
static int mine_check(const mine_job_t *job,u64_t n,u32_t zero_bits)
{
  u32_t hash[5];

  mine_job_hash(job,n,hash);
  return (hash[4] & mine_mask(zero_bits)) == 0u;
}

__attribute__((unused))
static int mine_slot_padding(u64_t before,u64_t after,u64_t *padding)
{
  for(u64_t n_blocks = 1u;n_blocks <= 2u;n_blocks++)
    for(u64_t k = 0u;k < 64u;k++)
    {
      u64_t nonce_pos = before + k;
      u64_t nonce_end = nonce_pos + MINE_NONCE_DIGITS;
      u64_t data_size = mine_padded_size(nonce_end + after);

      if(nonce_end % 4u == 0u && nonce_pos / 64u == (nonce_end - 1u) / 64u && data_size / 64u - nonce_pos / 64u == n_blocks)
      {
        *padding = k;
        return 0;
      }
    }
  return -1;
}

__attribute__((unused))
static int mine_read_file(const char *name,u08_t **bytes,u64_t *size)
{
  FILE *fp = fopen(name,"rb");

  if(fp == NULL)
  {
    fprintf(stderr,"mine_read_file(\"%s\"): unable to open file\n",name);
    return -1;
  }
  long length = (fseek(fp,0L,SEEK_END) == 0) ? ftell(fp) : -1L;
  if(length < 1L || (u64_t)length > MINE_MAX_FILE_SIZE || fseek(fp,0L,SEEK_SET) != 0)
  {
    fclose(fp);
    fprintf(stderr,"mine_read_file(\"%s\"): bad file size\n",name);
    return -1;
  }
  *bytes = (u08_t *)malloc((size_t)length);
  if(*bytes == NULL)
  {
    fclose(fp);
    fprintf(stderr,"mine_read_file(\"%s\"): out of memory\n",name);
    return -1;
  }
  if(fread((void *)*bytes,(size_t)1,(size_t)length,fp) != (size_t)length)
  {
    fclose(fp);
    free(*bytes);
    fprintf(stderr,"mine_read_file(\"%s\"): read error\n",name);
    return -1;
  }
  fclose(fp);
  *size = (u64_t)length;
  return 0;
}

#endif
