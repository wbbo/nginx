#include <ngx_htbl.h>

void *
ngx_htbl_alloc(ngx_htbl_t *htbl, size_t size)
{
    return htbl->ops.alloc(htbl->pool, size);
}

void
ngx_htbl_free(ngx_htbl_t *htbl, void *p)
{
    if (p) {
        htbl->ops.free(htbl->pool, p);
    }
}

void
ngx_htbl_get(ngx_htbl_t *htbl)
{
    htbl->used_entries++;
}

void
ngx_htbl_put(ngx_htbl_t *htbl)
{
    htbl->used_entries--;
}

ngx_int_t
ngx_htbl_insert(ngx_htbl_t *htbl, void *key, void *value)
{
    ngx_htbl_elm_t *elm;
    uint32_t index;
    uint64_t cycle;
    bool success;

    cycle = time(0);
    success = false;

    index = htbl->ops.hash(key);
    elm = NGX_HTBL_POS(htbl, index);

    for (index = 0; index < htbl->bucket_entries; index++) {
        if (elm->flag == NGX_HTBL_FLAG_FREE) {
            elm->flag = NGX_HTBL_FLAG_INUSE;
            elm->key = key;
            elm->value = value;
            elm->cycle = cycle;
            success = true;
            ngx_htbl_get(htbl);
            break;
        }
        else {
            // reuse if the entry stale when max_cycles set
            if (htbl->max_cycles && (cycle - elm->cycle > htbl->max_cycles)) {
                elm->key = key;
                elm->value = value;
                elm->cycle = cycle;
                success = true;
                break;
            }
            if (htbl->ops.compare(key, elm->key)) {
                // record already in htbl, insert failed.
                break;
            }
        }
        elm += 1;
    }

    if (success) {
        return NGX_OK;
    }

    return NGX_ERROR;
}

ngx_int_t
ngx_htbl_remove(ngx_htbl_t *htbl, void *key)
{
    ngx_htbl_elm_t *elm;
    uint32_t index;

    index = htbl->ops.hash(key);
    elm = NGX_HTBL_POS(htbl, index);

    for (index = 0; index < htbl->bucket_entries; index++) {
        if (elm->flag == NGX_HTBL_FLAG_INUSE) {
            if (htbl->ops.compare(key, elm->key)) {
                elm->flag = NGX_HTBL_FLAG_FREE;
                ngx_htbl_free(htbl, elm->key);
                ngx_htbl_free(htbl, elm->value);
                elm->key = NULL;
                elm->value = NULL;
                ngx_htbl_put(htbl);
                return NGX_OK;
            }
        }
        elm += 1;
    }

    // no such record in htbl
    return NGX_ERROR;
}

void *
ngx_htbl_search(ngx_htbl_t *htbl, void *key)
{
    ngx_htbl_elm_t *elm;
    uint32_t index;
    uint64_t cycle;

    cycle = time(0);

    index = htbl->ops.hash(key);
    elm = NGX_HTBL_POS(htbl, index);

    for (index = 0; index < htbl->bucket_entries; index++) {
        if (elm->flag == NGX_HTBL_FLAG_INUSE) {
            if (htbl->ops.compare(key, elm->key)) {
                return elm;
            } else {
                if (htbl->max_cycles && (cycle - elm->cycle > htbl->max_cycles)) {
                    elm->flag = NGX_HTBL_FLAG_FREE;
                    ngx_htbl_free(htbl, elm->key);
                    ngx_htbl_free(htbl, elm->value);
                    elm->key = NULL;
                    elm->value = NULL;
                    ngx_htbl_put(htbl);
                }
            }
        }
        elm += 1;
    }

    return NULL;
}

ngx_htbl_t *
ngx_htbl_create(void *pool, ngx_htbl_ops_t *ops, uint32_t bucket_num, uint32_t bucket_entries, uint64_t max_cycles)
{
    ngx_htbl_t *htbl;
    uint32_t nb_entries;
    size_t size;

    if ((bucket_entries % 2) || (bucket_num % 2)) {
        // please let these two parameters be power of 2
        return NULL;
    }

    nb_entries = bucket_num * bucket_entries;
    size = sizeof(ngx_htbl_t) + nb_entries * sizeof(ngx_htbl_elm_t);

    htbl = ops->alloc(pool, size);
    if (!htbl) {
        return NULL;
    }

    htbl->pool = pool;
    htbl->ops = *ops;
    htbl->bucket_entries = bucket_entries;
    htbl->nb_buckets = bucket_num;
    htbl->nb_entries = nb_entries;
    htbl->used_entries = 0;
    htbl->max_cycles = max_cycles;
    htbl->entry_mask = (htbl->nb_entries - 1) & ~(htbl->bucket_entries  - 1);

    return htbl;
}

void
ngx_htbl_destroy(ngx_htbl_t *htbl)
{
    // TODO: free all entries
    htbl->ops.free(htbl->pool, htbl);
}