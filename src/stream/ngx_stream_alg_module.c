/******************************************************************************

            版权所有 (C), 2019-2020, 绿盟科技

 ******************************************************************************
    文 件 名 : ngx_stream_alg_module.c
    版 本 号 : V1.0
    作    者 : wangpeng
    生成日期 : 2021年11月29日
    功能描述 : NGINX支持FTP ALG功能
    修改历史 :
******************************************************************************/

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <nginx.h>
#include <ngx_stream_alg_module.h>
#include <ngx_jhash.h>

#include <packet-dcom.h>

static ngx_stream_alg_ctx_t alg_ctx;

uint32_t ngx_stream_alg_hash(void *key)
{
    ngx_stream_alg_key_t *k = key;
    return ngx_jhash_1word(k->ip, JHASH_INITVAL);
}

bool ngx_stream_alg_compare(void *key1, void *key2)
{
    ngx_stream_alg_key_t *k1 = key1;
    ngx_stream_alg_key_t *k2 = key2;
    if (k1->ip == k2->ip) {
        return true;
    }
    return false;
}

ngx_stream_alg_port_t * ngx_stream_alg_get_port(ngx_stream_session_t *s)
{
    ngx_stream_proxy_srv_conf_t *pscf;
    ngx_stream_alg_port_t *alg_port;
    ngx_queue_t *p;

    if (s->alg_port) {
        alg_port = (ngx_stream_alg_port_t *)(s->alg_port);

        ngx_log_debug(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
            "stream %p alg_port %p port %d",
            s, alg_port, alg_port->port
        );

        return alg_port;
    }

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);
    if (!pscf) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "proxy srv conf null");
        return NULL;
    }

    if (ngx_queue_empty(&pscf->alg_port)
        || (pscf->alg_port_min > pscf->alg_port_max)) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
            "proxy srv conf %p alg port queue empty",
            pscf
        );

        return NULL;
    }

    p = ngx_queue_head(&pscf->alg_port);
    alg_port = ngx_queue_data(p, ngx_stream_alg_port_t, node);
    s->alg_port = alg_port;

    ngx_log_debug(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
        "stream %p alg port %p port %d",
        s, alg_port, alg_port->port
    );

    /**
     * move this node to queue tail. for next time, we will
     * get a new node. it's a simple implementation for alg_port
     * cycle.
     */
    ngx_queue_remove(p);
    ngx_queue_insert_tail(&pscf->alg_port, p);

    return alg_port;
}

void ngx_stream_alg_free_port(ngx_stream_session_t *s)
{
    ngx_stream_alg_port_t *alg_port;

    if (!s->alg_port) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "stream %p has no alg_port", s);
        return;
    }

    alg_port = (ngx_stream_alg_port_t *)(s->alg_port);

    ngx_log_debug(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
        "stream %p free alg_port %p port %d",
        s, alg_port, alg_port->port
    );
    s->alg_port = NULL;

    return;
}

ngx_int_t
ngx_stream_alg_add_listening(ngx_conf_t *cf, ngx_uint_t port, ngx_listening_t **listen)
{
    ngx_listening_t *ls;
    struct sockaddr_in addr;
    socklen_t len;

    len = sizeof(struct sockaddr_in);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    ls = ngx_create_listening(cf, (struct sockaddr *)&addr, len);
    if (!ls) {
        return NGX_ERROR;
    }

    ls->addr_ntop = 1;
    ls->handler = ngx_stream_init_connection;
    ls->pool_size = 256;
    ls->type = SOCK_STREAM;

#if 0
    cscf = addr->opt.ctx->srv_conf[ngx_stream_core_module.ctx_index];
    ls->logp = cscf->error_log;
#endif

    ls->logp = cf->log;
    ls->log.data = &ls->addr_text;
    ls->log.handler = ngx_accept_log_error;

    ls->backlog = 511;
    ls->rcvbuf = -1;
    ls->sndbuf = -1;

    ls->wildcard = 0;

    ls->keepalive = 0;

#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    ls->keepidle = 0;
    ls->keepintvl = 0;
    ls->keepcnt = 0;
#endif

#if (NGX_HAVE_INET6)
    ls->ipv6only = 1;
#endif

#if (NGX_HAVE_REUSEPORT)
    ls->reuseport = 0;
#endif

    /**
     * ls->servers is a complex struct generate at config phase. see stream
     * proxy module 'listen' command.
     *
     * because data session is related to ctrl session, we just 'copy' ctrl
     * session's ls->server to data session's ls->server. we deferred this
     * task to the moment when a data session is negotiated.
     */

    if (listen) {
        *listen = ls;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_stream_alg_ftp_resolve_addr(ngx_stream_session_t *s, u_char *addr, size_t size,
    unsigned int ip[4], unsigned int *port)
{
    unsigned int port1, port2;
    ngx_int_t rv;

    if (!ngx_strlchr(addr, addr + size - 1, ',')) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "format error: , not found");
        return NGX_ERROR;
    }

    rv = sscanf((const char*)addr, "%u,%u,%u,%u,%u,%u", &ip[0], &ip[1], &ip[2], &ip[3],
                        &port1, &port2);
    if (rv != 6) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "format error: address invalid");
        return NGX_ERROR;
    }

    if (port) {
        *port = port1 * 256 + port2;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_stream_alg_process_ftp(ngx_stream_session_t *s, ngx_buf_t *buffer)
{
    ngx_connection_t *c;
    ngx_socket_t fd;
    ngx_uint_t total_len;
    ngx_int_t rv;

    u_char *cmd, *p, *q;
    u_char cmd_pasv[] = "227 Entering Passive Mode (";
    u_char cmd_port[] = "PORT ";
    ngx_uint_t ftp_mode = 0; // 1-PASV 2-PORT

    c = s->connection;
    fd = c->fd;

    total_len = buffer->last - buffer->pos;
    if (total_len < 2) {
        ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "format error: truncated");
        return NGX_AGAIN;
    }

    cmd = buffer->pos;
    if (!ngx_strstrn(cmd + total_len - 2, CRLF, 2)) {
        ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "format error: CRLF not found");
        return NGX_AGAIN;
    }

    if (ngx_strstr(cmd, cmd_pasv)) {
        ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "FTP passive mode");

        p = ngx_strlchr(cmd, cmd + total_len - 1, '(');
        q = ngx_strlchr(cmd, cmd + total_len - 1, ')');
        if (!p || !q) {
            ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "format error: () not found");
            return NGX_OK;
        }
        ftp_mode = 1;
    }

    if (ngx_strstr(cmd, cmd_port)) {
        ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "FTP port mode");

        p = ngx_strlchr(cmd, cmd + total_len - 1, ' ');
        q = ngx_strlchr(cmd, cmd + total_len - 1, '\r');
        if (!p || !q) {
            ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "format error: ' \\r' not found");
            return NGX_OK;
        }
        ftp_mode = 2;
    }

    if (ftp_mode) {
        ngx_stream_proxy_srv_conf_t *pscf;
        ngx_stream_alg_port_t *alg_port;
        ngx_listening_t *ls;
        ngx_htbl_t *htbl;

        unsigned int ip1[4] = {0};     // resovled upstream ip
        unsigned int port1 = 0;        // resovled upstream port
        unsigned int ip2[4] = {0};     // proxy ip
        unsigned int port2 = 0;        // proxy port
        uint32_t downstream_ip;

        struct sockaddr_in addr;
        socklen_t len;
        u_char addr_str[INET_ADDRSTRLEN];

        p += 1;
        q -= 1;

        // resolve upstream address
        rv = ngx_stream_alg_ftp_resolve_addr(s, p, q - p + 1, ip1, &port1);
        if (rv != NGX_OK) {
            ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "ftp alg resolve upstream address failed");
            return NGX_ERROR;
        }

        // resolve proxy address
        if (ftp_mode == 1) { // PASV mode
            ; // fd = fd
        }
        if (ftp_mode == 2) { // PORT mode
            fd = s->upstream->peer.connection->fd;
        }

        len = sizeof(struct sockaddr_in);
        ngx_memzero(&addr, len);
        if (getsockname(fd, (struct sockaddr *)&addr, &len)) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "invalid socket fd");
            return NGX_ERROR;
        }

        ngx_memzero(addr_str, INET_ADDRSTRLEN);
        ngx_inet_ntop(addr.sin_family, (struct sockaddr *)&addr.sin_addr, addr_str, INET_ADDRSTRLEN);

        rv = sscanf((const char *)addr_str, "%u.%u.%u.%u", &ip2[0], &ip2[1], &ip2[2], &ip2[3]);
        if(rv != 4 ) {
            ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "invalid address");
            return NGX_ERROR;
        }

        // resolve downstream address
        len = sizeof(struct sockaddr_in);
        ngx_memzero(&addr, len);
        if (getpeername(fd, (struct sockaddr *)&addr, &len)) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "invalid socket fd");
            return NGX_ERROR;
        }
        downstream_ip = addr.sin_addr.s_addr;

        // select listening port
        pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);
        if (!pscf) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "proxy srv conf null");
            return NGX_ERROR;
        }

        if (pscf->alg_port_min != NGX_CONF_UNSET_UINT) {
            /**
             * user defined, open listening at config phase, and never
             * close until the process exit. see stream proxy module
             * postconfiguration.
             */
            alg_port = ngx_stream_alg_get_port(s);
            if (!alg_port) {
                ngx_log_error(NGX_LOG_ERR, c->log, 0, "no alg port available");
                return NGX_ERROR;
            }
            port2 = alg_port->port;
            ls = alg_port->listen;
            htbl = ls->data_link;
            ls->servers = c->listening->servers;
        } else {
            /**
             * TODO : system auto alloc.
             */
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "not supported yet");
            return NGX_ERROR;
        }

        /**
         * establiash relationship between downstream and upstream for upcoming
         * data-link.
         *      (downstream ctrl-link ip, listen) -> upstream address
         */
        ngx_stream_alg_key_t *key = ngx_htbl_pcalloc(htbl, sizeof(ngx_stream_alg_key_t));
        if (!key) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "no mem for alg key");
            return NGX_ERROR;
        }
        ngx_stream_alg_val_t *val = ngx_htbl_pcalloc(htbl, sizeof(ngx_stream_alg_val_t));
        if (!val) {
            ngx_htbl_pfree(htbl, key);
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "no mem for alg key");
            return NGX_ERROR;
        }
        key->ip = downstream_ip;

        ngx_memzero(addr_str, INET_ADDRSTRLEN);
        ngx_snprintf(addr_str, INET_ADDRSTRLEN, "%ud.%ud.%ud.%ud", ip1[0], ip1[1], ip1[2], ip1[3]);
        val->addr.sin_family = AF_INET;
        val->addr.sin_port = htons(port1);
        val->addr.sin_addr.s_addr = ngx_inet_addr(addr_str, ngx_strlen(addr_str));
        val->peer.sockaddr = (struct sockaddr *)&val->addr;
        val->peer.socklen = sizeof(struct sockaddr_in);
        val->peer.naddrs = 1;
        val->peer.port = htons(port1);
        val->peer.no_port = 0;

        rv = ngx_htbl_insert(htbl, key, val);
        if (rv != NGX_OK) {
            ngx_htbl_pfree(htbl, key);
            ngx_htbl_pfree(htbl, val);
            return NGX_ERROR;
        }

        /**
         * modify the packet, switch orignal address to proxy address.
         */
        ngx_memset(buffer->pos, 0, total_len);

        if (ftp_mode == 1) { // PASV mode
            ngx_snprintf(buffer->pos, 80, "227 Entering Passive Mode \
                    (%ud,%ud,%ud,%ud,%ud,%ud).\r\n",
                    ip2[0], ip2[1], ip2[2], ip2[3],
                    port2 / 256,
                    port2 % 256
            );
        }

        if (ftp_mode == 2) { // PORT mode
            ngx_snprintf(buffer->pos, 80, "PORT %ud,%ud,%ud,%ud,%ud,%ud\r\n",
                    ip2[0], ip2[1], ip2[2], ip2[3],
                    port2 / 256,
                    port2 % 256
            );
        }

        buffer->last = buffer->pos + ngx_strlen(buffer->pos);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_stream_alg_process_opcda(ngx_stream_session_t *s, ngx_buf_t *buffer)
{
    ngx_stream_alg_port_t *alg_port;
    ngx_uint_t port;
    struct sockaddr_in addr;
    socklen_t len;
    ngx_socket_t fd;

    ngx_int_t offset, endian;
    dcom_resp_t type;
    filter_dcom_data_t d;

    ngx_listening_t *ls;
    ngx_htbl_t *htbl;
    ngx_stream_alg_key_t *key;
    ngx_stream_alg_val_t *val;

    ngx_int_t rv;

    ls = NULL;
    htbl = NULL;
    alg_port = NULL;
    key = NULL;
    val = NULL;
    port = 0;

    // dcom protocol precheck
    rv = dissect_dcom_precheck(buffer, 0);
    if (rv == NGX_DECLINED) {
        return NGX_OK;
    }

    ngx_memzero(&d, sizeof(filter_dcom_data_t));

    // resolve proxy address
    len = sizeof(struct sockaddr_in);
    ngx_memzero(&addr, len);
    fd = s->connection->fd; // local address
    if (getsockname(fd, (struct sockaddr *)&addr, &len)) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "invalid socket fd");
        return NGX_ERROR;
    }

    ngx_inet_ntop(addr.sin_family,
        (struct sockaddr *)&addr.sin_addr,
        d.iip,
        INET_ADDRSTRLEN
    );

    // dissect and modify the packet
    offset = dissect_dcom_resp_hdr(buffer, 0, &type, &endian);
    if ((type == DCOM_RESP_RESOLVE_OXID2) || (type == DCOM_RESP_CREATE_INSTANCE)) { // response has dynamic port
         /**
         * data link port come from:
         * 1. system auto alloc when a router be used.
         * 2. user defined when a firewall be used.
         */
        ngx_stream_proxy_srv_conf_t *pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);
        if (!pscf) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "proxy srv conf null");
            return NGX_ERROR;
        }

        if (pscf->alg_port_min != NGX_CONF_UNSET_UINT) { // user defined
            alg_port = ngx_stream_alg_get_port(s);
            if (!alg_port) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "no alg port available");
                return NGX_ERROR;
            }
            port = alg_port->port;
            ls = alg_port->listen;
            htbl = ls->data_link;
        } else { // system auto alloc
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "not supported yet");
            return NGX_ERROR;
        }
    }

    d.iport = port;
    buffer->priv = &d;

    rv = dissect_dcom_resp(buffer, offset, type, endian, true);
    if (rv == NGX_DECLINED) {
        /**
         * no dynamic port in this packet, all work done.
         */
        goto done;
    }

    if (!htbl || !port) {
        goto done;
    }

    if (!d.oport) { // resolve dynamic port failed
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "opcda resolve dynamic port failed");
        goto err;
    }

    key = ngx_htbl_pcalloc(htbl, sizeof(ngx_stream_alg_key_t));
    if (!key) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "no memory");
        goto err;
    }

    val = ngx_htbl_pcalloc(htbl, sizeof(ngx_stream_alg_val_t));
    if (!val) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "no memory");
        goto err;
    }

    // resolve downstream address
    len = sizeof(struct sockaddr_in);
    ngx_memzero(&addr, len);
    if (getpeername(fd, (struct sockaddr *)&addr, &len)) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "invalid socket fd");
        goto err;
    }
    key->ip = addr.sin_addr.s_addr;

    // resolve upstream address
    len = sizeof(struct sockaddr_in);
    ngx_memzero(&addr, len);
    fd = s->upstream->peer.connection->fd; // upstream address
    if (getpeername(fd, (struct sockaddr *)&addr, &len)) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "invalid socket fd");
        goto err;
    }

    val->addr = addr;
    val->addr.sin_port = htons(d.oport);
    val->peer.sockaddr = (struct sockaddr *)&val->addr;
    val->peer.socklen = sizeof(struct sockaddr_in);
    val->peer.naddrs = 1;
    val->peer.port = htons(d.oport);
    val->peer.no_port = 0;

    rv = ngx_htbl_insert(htbl, key, val);
    if (rv !=  NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "ngx htbl insert failed");
        goto err;
    }

done:
    return NGX_OK;

err:
    if (alg_port) {
        ngx_stream_alg_free_port(s);
    }
    if (key) {
        ngx_htbl_pfree(htbl, key);
    }
    if (val) {
        ngx_htbl_pfree(htbl, val);
    }

    return NGX_ERROR;
}

static ngx_int_t ngx_stream_alg_process(ngx_event_t *ev,
        ngx_int_t stream_direction)
{
    ngx_connection_t *c;
    ngx_stream_session_t *s;
    ngx_stream_upstream_t *u;
    size_t size;
    ssize_t n;
    ngx_chain_t *chain;
    ngx_int_t rc;
    ngx_stream_core_srv_conf_t *cscf;
    ngx_stream_proxy_srv_conf_t *pscf;

    c = ev->data;
    s = c->data;
    u = s->upstream;

    cscf = ngx_stream_get_module_srv_conf(s, ngx_stream_core_module);
    if (!cscf) {
        ngx_log_error(NGX_LOG_ERR, c->log, NGX_EINVAL, "stream core srv conf null");
        return NGX_ERROR;
    }

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);
    if (!pscf) {
        ngx_log_error(NGX_LOG_ERR, c->log, NGX_EINVAL, "stream proxy srv conf null");
        return NGX_ERROR;
    }

    if (c->read->timedout) {
    } else if (c->read->timer_set) {
    } else {
    }

    if (!c->buffer) {
        c->buffer = ngx_create_temp_buf(c->pool, cscf->preread_buffer_size);
        if (!c->buffer) {
            ngx_log_error(NGX_LOG_ERR, c->log, NGX_ENOMEM, "ngx create temp buf failed");
            return NGX_ERROR;
        }
    }

    size = c->buffer->end - c->buffer->last;
    if (!size) {
        ngx_log_error(NGX_LOG_ERR, c->log, NGX_ENOSPC, "buffer full");
        return NGX_ERROR;
    }

    if (c->read->eof) {
        ngx_log_debug(NGX_LOG_DEBUG, c->log, 0, "read eof");
        return NGX_OK;
    }

    if (!c->read->ready) {
        ngx_log_debug(NGX_LOG_DEBUG, c->log, 0, "read not ready");
        return NGX_OK;
    }

    n = c->recv(c, c->buffer->last, size);
    if (n == NGX_ERROR || n == 0) {
        if (ngx_handle_read_event(c->read, NGX_CLOSE_EVENT) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx handle read event failed");
            return NGX_ERROR;
        }
        return NGX_OK;
    }

    if (n == NGX_AGAIN) {
        ngx_log_debug(NGX_LOG_DEBUG, c->log, 0, "try again");
        return NGX_OK;
    }

    c->buffer->last += n;

    /**
     * only OPC_CLASSIC and FTP has dynamic port, other alg_proto
     * just let pass.
     */

    if (pscf->alg_proto == NGX_STREAM_ALG_PROTO_FTP) {
        rc = ngx_stream_alg_process_ftp(s, c->buffer);
        if (rc == NGX_ERROR || rc == NGX_AGAIN) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx stream alg process ftp failed");
            return rc;
        }
    }
    if (pscf->alg_proto == NGX_STREAM_ALG_PROTO_OPC_CLASSIC) {
        rc = ngx_stream_alg_process_opcda(s, c->buffer);
        if (rc == NGX_ERROR || rc == NGX_AGAIN) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx stream alg process opcda failed");
            return rc;
        }
    }

    if (c->buffer && c->buffer->pos < c->buffer->last) {
        chain = ngx_chain_get_free_buf(c->pool, &u->free);
        if (!chain) {
            ngx_log_error(NGX_LOG_ERR, c->log, NGX_ENOENT, "no chain found for upstream");
            return NGX_ERROR;
        }

        *chain->buf = *c->buffer;
        chain->buf->tag = (ngx_buf_tag_t) &ngx_stream_alg_module;
        chain->buf->flush = 1;

        if (stream_direction == NGX_STREAM_ALG_UPSTREAM) {
            chain->next = u->downstream_out;
            u->downstream_out = chain;
        } else {
            chain->next = u->upstream_out;
            u->upstream_out = chain;
        }
    }

    c->buffer->pos = c->buffer->last;
    return NGX_OK;
}

static void ngx_stream_alg_upstream_handler(ngx_event_t *ev)
{
    ngx_stream_alg_ctx_t *ctx;
    ngx_int_t rc;
    ngx_connection_t *c;
    ngx_stream_session_t *s;

    c = ev->data;
    s = c->data;

    rc = ngx_stream_alg_process(ev, NGX_STREAM_ALG_UPSTREAM);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx stream alg process upstream failed");
        return;
    }

    ctx = ngx_stream_alg_get_ctx(s);
    ctx->ori_upstream_handler(ev);

    return;
}

static void
ngx_stream_alg_downstream_handler(ngx_event_t *ev)
{
    ngx_stream_alg_ctx_t *ctx;
    ngx_int_t rc;
    ngx_connection_t *c;
    ngx_stream_session_t *s;

    c = ev->data;
    s = c->data;

    rc = ngx_stream_alg_process(ev, NGX_STREAM_ALG_DOWNSTREAM);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx stream alg process downstream failed");
        return;
    }

    ctx = ngx_stream_alg_get_ctx(s);
    ctx->ori_downstream_handler(ev);

    return;
}

static ngx_event_handler_pt
ngx_stream_alg_checkout_handler(ngx_stream_session_t *s, ngx_event_handler_pt handler,
        ngx_int_t up_down)
{
    ngx_stream_alg_ctx_t *ctx;

    ctx = ngx_stream_alg_get_ctx(s);

    if (up_down == NGX_STREAM_ALG_DOWNSTREAM) {
        if (!ctx->ori_downstream_handler) {
            ctx->ori_downstream_handler = handler;
        }
        return ctx->alg_downstream_handler;
    }

    if (up_down == NGX_STREAM_ALG_UPSTREAM) {
        if (!ctx->ori_upstream_handler) {
            ctx->ori_upstream_handler = handler;
        }
        return ctx->alg_upstream_handler;
    }

    return NULL;
}

ngx_stream_alg_ctx_t *
ngx_stream_alg_get_ctx(ngx_stream_session_t *s)
{
    ngx_stream_alg_ctx_t *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_alg_module);
    if (!ctx) {
        ctx = &alg_ctx;
        ngx_stream_set_ctx(s, ctx, ngx_stream_alg_module);
    }

    return ctx;
}

static ngx_int_t
ngx_stream_alg_handler(ngx_stream_session_t *s)
{
    return NGX_OK;
}

static ngx_int_t
ngx_stream_alg_postconfiguration(ngx_conf_t *cf)
{
    ngx_stream_handler_pt        *h;
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_STREAM_PREREAD_PHASE].handlers);
    if (!h) {
        return NGX_ERROR;
    }

    *h = ngx_stream_alg_handler;

    alg_ctx.alg_upstream_handler = ngx_stream_alg_upstream_handler;
    alg_ctx.ori_upstream_handler = NULL;
    alg_ctx.alg_downstream_handler = ngx_stream_alg_downstream_handler;
    alg_ctx.ori_downstream_handler = NULL;
    alg_ctx.checkout_handler = ngx_stream_alg_checkout_handler;

    // dcom_do_test();

    return NGX_OK;
}

static ngx_command_t ngx_stream_alg_commands[] = {
    ngx_null_command
};

static ngx_stream_module_t ngx_stream_alg_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_stream_alg_postconfiguration,      /* postconfiguration */
    NULL,                                  /* create main conf */
    NULL,                                  /* init main conf */
    NULL,                                  /* create server conf */
    NULL,                                  /* merge server conf */
};

ngx_module_t ngx_stream_alg_module = {
    NGX_MODULE_V1,
    &ngx_stream_alg_module_ctx,            /* module context */
    ngx_stream_alg_commands,               /* module directives */
    NGX_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};
