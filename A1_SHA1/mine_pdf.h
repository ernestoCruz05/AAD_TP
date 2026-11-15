#ifndef MINE_PDF
#define MINE_PDF

#include "mine.h"

__attribute__((unused)) static int pdf_load(const char *name, mine_file_t *f) {
    static const char key[] = "startxref";
    const u64_t key_len = sizeof(key) - 1u;
    u08_t *bytes;
    u64_t size, start, padding;

    if (mine_read_file(name, &bytes, &size) != 0)
        return -1;
    start = size;
    if (size >= key_len && memcmp(bytes, "%PDF-", (size_t)5) == 0)
        for (u64_t i = size - key_len + 1u; i-- > 0u;)
            if (memcmp(&bytes[i], key, key_len) == 0) {
                start = i;
                break;
            }
    if (start == size ||
        mine_slot_padding(start + 1u, 1u + size - start, &padding) != 0) {
        free(bytes);
        fprintf(stderr,
                "pdf_load(\"%s\"): not a PDF file with a usable startxref\n",
                name);
        return -1;
    }
    f->file_size = size + 2u + padding + MINE_NONCE_DIGITS;
    f->data_size = mine_padded_size(f->file_size);
    f->data = (u08_t *)malloc(f->data_size);
    if (f->data == NULL) {
        free(bytes);
        fprintf(stderr, "pdf_load(\"%s\"): out of memory\n", name);
        return -1;
    }
    f->nonce_pos = start + 1u + padding;
    f->nonce_len = MINE_NONCE_DIGITS;
    f->kind = MINE_DIGITS;
    f->crc_pos = 0u;
    f->crc_from = 0u;
    memcpy(f->data, bytes, start);
    f->data[start] = '%';
    memset(&f->data[start + 1u], '0', padding + MINE_NONCE_DIGITS);
    f->data[f->nonce_pos + f->nonce_len] = '\n';
    memcpy(&f->data[f->nonce_pos + f->nonce_len + 1u], &bytes[start],
           size - start);
    free(bytes);
    mine_pad(f);
    return 0;
}

#endif
