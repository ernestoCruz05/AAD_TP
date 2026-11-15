#ifndef MINE_FILE
#define MINE_FILE

#include "mine.h"
#include "mine_pdf.h"

__attribute__((unused))
static int mine_load(const char *name,mine_file_t *f)
{
  const char *extension = strrchr(name,'.');

  if(extension != NULL && strcmp(extension,".pdf") == 0)
    return pdf_load(name,f);
  fprintf(stderr,"mine_load(\"%s\"): unknown file type\n",name);
  return -1;
}

__attribute__((unused))
static int mine_save(const char *name,const mine_file_t *f)
{
  FILE *fp = fopen(name,"wb");

  if(fp == NULL)
  {
    fprintf(stderr,"mine_save(\"%s\"): unable to create file\n",name);
    return -1;
  }
  if(fwrite((const void *)f->data,(size_t)1,(size_t)f->file_size,fp) != (size_t)f->file_size)
  {
    fclose(fp);
    fprintf(stderr,"mine_save(\"%s\"): write error\n",name);
    return -1;
  }
  if(fclose(fp) != 0)
  {
    fprintf(stderr,"mine_save(\"%s\"): write error\n",name);
    return -1;
  }
  return 0;
}

#endif
