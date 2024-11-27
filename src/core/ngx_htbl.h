#ifndef _NGX_HTBL_H_INCLUDED_
#define _NGX_HTBL_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

#include <stdbool.h>

#define NGX_HTBL_MAX_CYCLE      30
#define NGX_HTBL_BUCKET_ENTRIES 4
#define NGX_HTBL_BUCKET_NUM     ((uint32_t)1 << 16)

#define	NGX_HTBL_POS(htbl, index) ((htbl)->elms + ((index) & (htbl)->entry_mask))

typedef enum {
	NGX_HTBL_FLAG_FREE  = 0,
	NGX_HTBL_FLAG_INUSE = 1,
} ngx_htbl_flag_t;

typedef struct {
	ngx_htbl_flag_t flag;
	uint64_t cycle;
	void *key;
	void *value;
} ngx_htbl_elm_t;

typedef struct {
	uint32_t (*hash)(void *key);
	bool (*compare)(void *key1, void *key2);
	void* (*alloc)(void *pool, size_t size);
	void (*free)(void *pool, void *p);
} ngx_htbl_ops_t;

typedef struct {
	void *pool;
	ngx_htbl_ops_t ops;
	uint32_t bucket_entries;
	uint32_t nb_buckets;
	uint32_t nb_entries;
	uint32_t used_entries;
	uint32_t entry_mask;
	uint64_t max_cycles;
	ngx_htbl_elm_t elms[0];
} ngx_htbl_t;

void *
ngx_htbl_alloc(ngx_htbl_t *htbl, size_t size);

void
ngx_htbl_free(ngx_htbl_t *htbl, void *p);

void
ngx_htbl_get(ngx_htbl_t *htbl);

void
ngx_htbl_put(ngx_htbl_t *htbl);

ngx_int_t
ngx_htbl_insert(ngx_htbl_t *htbl, void *key, void *value);

ngx_int_t
ngx_htbl_remove(ngx_htbl_t *htbl, void *key);

void *
ngx_htbl_search(ngx_htbl_t *htbl, void *key);

ngx_htbl_t *
ngx_htbl_create(void *pool, ngx_htbl_ops_t *ops, uint32_t bucket_num, uint32_t bucket_entries, uint64_t max_cycles);

void
ngx_htbl_destroy(ngx_htbl_t *htbl);

#endif /** _NGX_HTBL_H_INCLUDED_ */