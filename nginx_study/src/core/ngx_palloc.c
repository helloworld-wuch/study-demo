
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


static ngx_inline void *ngx_palloc_small(ngx_pool_t *pool, size_t size,
    ngx_uint_t align);
static void *ngx_palloc_block(ngx_pool_t *pool, size_t size);
static void *ngx_palloc_large(ngx_pool_t *pool, size_t size);


ngx_pool_t *
ngx_create_pool(size_t size, ngx_log_t *log)
{
    ngx_pool_t  *p;

    p = ngx_memalign(NGX_POOL_ALIGNMENT, size, log); //分配一块根据size大小，并以16字节对齐（是要16字节的整数倍）的内存。
    if (p == NULL) {
        return NULL;
    }

    p->d.last = (u_char *) p + sizeof(ngx_pool_t); //指向可以分配内存的起始地址
    p->d.end = (u_char *) p + size; //指向整个内存块的尾部地址
    p->d.next = NULL; //下一个内存池
    p->d.failed = 0;

    size = size - sizeof(ngx_pool_t); //减去头部，就是可分配的大小
    p->max = (size < NGX_MAX_ALLOC_FROM_POOL) ? size : NGX_MAX_ALLOC_FROM_POOL;  //不超过(uintptr_t)-1的大小，也就是uintptr_t类型的最大值

    p->current = p; //指向当前的内存池
    p->chain = NULL;
    p->large = NULL;
    p->cleanup = NULL;
    p->log = log;

    return p;
}


void
ngx_destroy_pool(ngx_pool_t *pool)
{
    ngx_pool_t          *p, *n;
    ngx_pool_large_t    *l;
    ngx_pool_cleanup_t  *c;

    for (c = pool->cleanup; c; c = c->next) {  //遍历chunck，并调用当前chunck的清理chunck内存的回调函数
        if (c->handler) {
            ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, pool->log, 0,
                           "run cleanup: %p", c);
            c->handler(c->data);
        }
    }

#if (NGX_DEBUG)

    /*
     * we could allocate the pool->log from this pool
     * so we cannot use this log while free()ing the pool
     */

    for (l = pool->large; l; l = l->next) {
        ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, pool->log, 0, "free: %p", l->alloc);
    }

    for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
        ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, pool->log, 0,
                       "free: %p, unused: %uz", p, p->d.end - p->d.last);

        if (n == NULL) {
            break;
        }
    }

#endif
    //清理大块
    for (l = pool->large; l; l = l->next) {
        if (l->alloc) {
            ngx_free(l->alloc);
        }
    }
    //释放每个chunck的头部
    for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
        ngx_free(p);

        if (n == NULL) {
            break;
        }
    }
}

/*
 * 重置内存池
 * 1、释放所有大块
 * 2、将所有chunk中的last指针重置，也就是放在头部的后面。不需要清空chunck里面的数据，使用的时候直接覆盖就行了
 */
void
ngx_reset_pool(ngx_pool_t *pool)
{
    ngx_pool_t        *p;
    ngx_pool_large_t  *l;

    //释放所有的大块内存（但是，大块的链表节点依然还在，因为它存储在chunck里面）
    for (l = pool->large; l; l = l->next) {
        if (l->alloc) {
            ngx_free(l->alloc);
        }
    }

    //将chunck中last指针初始化，chunck内存中的数据不需要清理，因为，可以直接覆盖
    for (p = pool; p; p = p->d.next) {
        p->d.last = (u_char *) p + sizeof(ngx_pool_t);
        p->d.failed = 0;
    }

    pool->current = pool;
    pool->chain = NULL;
    pool->large = NULL;
}

/*
 * 从内存池中取一块来进行分配。
 * 如果小于chunck可以分配的最大大小，那么就分配到chunck中(小块)
 * 如果大于chunck可以分配的最大大小，那么就分配到大块中
 */
void *
ngx_palloc(ngx_pool_t *pool, size_t size)
{
#if !(NGX_DEBUG_PALLOC)
    if (size <= pool->max) {
        return ngx_palloc_small(pool, size, 1);
    }
#endif

    return ngx_palloc_large(pool, size);
}


void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
#if !(NGX_DEBUG_PALLOC)
    if (size <= pool->max) {
        return ngx_palloc_small(pool, size, 0); //不适用内存对齐
    }
#endif

    return ngx_palloc_large(pool, size);
}

/*
 * 在chunck(小块）中分配一块内存
 * 遍历chunck链，如果找到一块可以存放的空间，就返回可分配的内存空间的起始地址
 * 如果找不到，就创建一个新的chunck
 */
static ngx_inline void *
ngx_palloc_small(ngx_pool_t *pool, size_t size, ngx_uint_t align)
{
    u_char      *m;
    ngx_pool_t  *p;

    p = pool->current;

    do {
        m = p->d.last; //指向当前块，还未分配的头部

        if (align) { //如果使用内存对齐，那么下面就执行对齐。比如按照4个字节对齐，内存已经使用了14字节，那么都当作已经用完了16个字节，从这后面再开始使用
            m = ngx_align_ptr(m, NGX_ALIGNMENT);
        }

        if ((size_t) (p->d.end - m) >= size) { //如果当前小块有空间可以分配，那么就返回内存可分配的起始地址
            p->d.last = m + size;

            return m;
        }

        p = p->d.next; //如果当前chunck没有内存可以供当前大小内存分配，就查找下一个chunck

    } while (p);

    return ngx_palloc_block(pool, size); //遍历完所有chunck都没有可以分配的，那么就新创建一个chunck
}

/*
 * 创建一块新的chunk内存空间，也就是在ngx_palloc_small的chunck链中没找到可以分配的空间，那么就创建一块。
 */
static void *
ngx_palloc_block(ngx_pool_t *pool, size_t size)
{
    u_char      *m;
    size_t       psize;
    ngx_pool_t  *p, *new;

    psize = (size_t) (pool->d.end - (u_char *) pool); //去除头部后，可真正使用得内存空间大小

    m = ngx_memalign(NGX_POOL_ALIGNMENT, psize, pool->log); //分配一块psize大小的内存
    if (m == NULL) {
        return NULL;
    }

    new = (ngx_pool_t *) m;

    new->d.end = m + psize;
    new->d.next = NULL;
    new->d.failed = 0;

    m += sizeof(ngx_pool_data_t);
    m = ngx_align_ptr(m, NGX_ALIGNMENT);
    new->d.last = m + size;
    //通过遍历，来获得链表尾部
    for (p = pool->current; p->d.next; p = p->d.next) {
        if (p->d.failed++ > 4) { //如果failed > 4, 就漏过这个chunck(也就是说每个块，在查找块的时候只允许失败4次，失败4次后，让current指向该节点的下一个)
            pool->current = p->d.next;
        }
    }
    //链表尾部用来存新的chunck
    p->d.next = new;

    return m;
}

/*
 * 分配一个大块节点（节点存到(chunck)小块里面），通过链表的方式，串起来。
 * 然后节点上的指针，指向大块，通过这种方式，将大块组织起来
 */
static void *
ngx_palloc_large(ngx_pool_t *pool, size_t size)
{
    void              *p;
    ngx_uint_t         n;
    ngx_pool_large_t  *large;

    p = ngx_alloc(size, pool->log);
    if (p == NULL) {
        return NULL;
    }

    n = 0;
    //遍历大块的链表节点，找到一个空的节点来用
    for (large = pool->large; large; large = large->next) {
        if (large->alloc == NULL) { //如果之前创建的大块已经被释放，但是节点还在，那么就利用这个节点，指向新的大块内存。
            large->alloc = p;
            return p;
        }

        if (n++ > 3) { //如果查找3次还没有找到空的节点，那么就直接break，然后采用头插法
            break;
        }
    }

    large = ngx_palloc_small(pool, sizeof(ngx_pool_large_t), 1); //分配一个链表的节点（用于指向大块），这个节点是存放在小块里的
    if (large == NULL) {
        ngx_free(p);
        return NULL;
    }

    //插入头部
    large->alloc = p;
    large->next = pool->large;
    pool->large = large;

    return p;
}

/*
 * 可以自定义对齐字节大小，创建一块大块内存
 */
void *
ngx_pmemalign(ngx_pool_t *pool, size_t size, size_t alignment)
{
    void              *p;
    ngx_pool_large_t  *large;

    p = ngx_memalign(alignment, size, pool->log);
    if (p == NULL) {
        return NULL;
    }

    large = ngx_palloc_small(pool, sizeof(ngx_pool_large_t), 1);
    if (large == NULL) {
        ngx_free(p);
        return NULL;
    }

    large->alloc = p;
    large->next = pool->large;
    pool->large = large;

    return p;
}

/*
 * 释放内存池，小块不会被释放(小块在ngx_destory_pool时释放)，只有大块释放了
 */
ngx_int_t
ngx_pfree(ngx_pool_t *pool, void *p)
{
    ngx_pool_large_t  *l;

    for (l = pool->large; l; l = l->next) {
        if (p == l->alloc) {
            ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, pool->log, 0,
                           "free: %p", l->alloc);
            ngx_free(l->alloc);
            l->alloc = NULL;

            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


void *
ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
    void *p;

    p = ngx_palloc(pool, size);
    if (p) {
        ngx_memzero(p, size);
    }

    return p;
}


ngx_pool_cleanup_t *
ngx_pool_cleanup_add(ngx_pool_t *p, size_t size)
{
    ngx_pool_cleanup_t  *c;

    c = ngx_palloc(p, sizeof(ngx_pool_cleanup_t));
    if (c == NULL) {
        return NULL;
    }

    if (size) {
        c->data = ngx_palloc(p, size);
        if (c->data == NULL) {
            return NULL;
        }

    } else {
        c->data = NULL;
    }

    c->handler = NULL;
    c->next = p->cleanup;

    p->cleanup = c;

    ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, p->log, 0, "add cleanup: %p", c);

    return c;
}


void
ngx_pool_run_cleanup_file(ngx_pool_t *p, ngx_fd_t fd)
{
    ngx_pool_cleanup_t       *c;
    ngx_pool_cleanup_file_t  *cf;

    for (c = p->cleanup; c; c = c->next) {
        if (c->handler == ngx_pool_cleanup_file) {

            cf = c->data;

            if (cf->fd == fd) {
                c->handler(cf);
                c->handler = NULL;
                return;
            }
        }
    }
}


void
ngx_pool_cleanup_file(void *data)
{
    ngx_pool_cleanup_file_t  *c = data;

    ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, c->log, 0, "file cleanup: fd:%d",
                   c->fd);

    if (ngx_close_file(c->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", c->name);
    }
}


void
ngx_pool_delete_file(void *data)
{
    ngx_pool_cleanup_file_t  *c = data;

    ngx_err_t  err;

    ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, c->log, 0, "file cleanup: fd:%d %s",
                   c->fd, c->name);

    if (ngx_delete_file(c->name) == NGX_FILE_ERROR) {
        err = ngx_errno;

        if (err != NGX_ENOENT) {
            ngx_log_error(NGX_LOG_CRIT, c->log, err,
                          ngx_delete_file_n " \"%s\" failed", c->name);
        }
    }

    if (ngx_close_file(c->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", c->name);
    }
}


#if 0

static void *
ngx_get_cached_block(size_t size)
{
    void                     *p;
    ngx_cached_block_slot_t  *slot;

    if (ngx_cycle->cache == NULL) {
        return NULL;
    }

    slot = &ngx_cycle->cache[(size + ngx_pagesize - 1) / ngx_pagesize];

    slot->tries++;

    if (slot->number) {
        p = slot->block;
        slot->block = slot->block->next;
        slot->number--;
        return p;
    }

    return NULL;
}

#endif
