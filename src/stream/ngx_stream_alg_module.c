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

#include <packet-dcom.h>

ngx_int_t ngx_stream_alg_get_port(ngx_stream_session_t *s)
{
    ngx_stream_proxy_srv_conf_t *pscf;
    ngx_queue_t *q;

    if (s->alg_port) { // already have one
        return NGX_OK;
    }

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    if (ngx_queue_empty(&pscf->alg_port)) { // no port available
        return NGX_ERROR;
    }

    q = ngx_queue_head(&pscf->alg_port);
    s->alg_port = ngx_queue_data(q, ngx_stream_alg_port_t, node);

    // remove the node from queue
    ngx_queue_remove(q);

    return NGX_OK;
}

void ngx_stream_alg_free_port(ngx_stream_session_t *s)
{
    ngx_stream_proxy_srv_conf_t *pscf;
    ngx_stream_alg_port_t *alg_port;

    if (!s->alg_port) {
        return;
    }

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    alg_port = (ngx_stream_alg_port_t *)(s->alg_port);

    // free to head for next time use
    s->alg_port = NULL;
    ngx_queue_insert_head(&pscf->alg_port, &alg_port->node);

    return;
}

static ngx_int_t ngx_stream_alg_new_listen(ngx_stream_session_t *s, ngx_uint_t port)
{
    ngx_connection_t *c;
    ngx_listening_t *ori, *new;
    struct sockaddr_in *addr, addr2;
    socklen_t len;
    ngx_uint_t _port;

    c = s->connection;
    ori = c->listening;

    if (!ori) {
        ngx_log_error(NGX_LOG_ERR, c->log, NGX_EINVAL, "connection orignal listening null");
        return NGX_ERROR;
    }

    len = sizeof(struct sockaddr_in);
    addr = (struct sockaddr_in *)ngx_pcalloc(c->pool, len);
    if (!addr) {
        ngx_log_error(NGX_LOG_ERR, c->log, NGX_ENOMEM, "no memory");
        return NGX_ERROR;
    }
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    addr->sin_addr.s_addr = INADDR_ANY;

    new = ngx_pcalloc(c->pool, sizeof(ngx_listening_t));
    *new = *ori;
    new->ignore = 0;
    new->fd = -1;
    new->inherited = 0;
    new->reuseport = 0;
    new->sockaddr = (struct sockaddr *)addr;
    new->parent_stream_session = s;
    new->worker = ngx_worker;
    new->addr_text.len = INET_ADDRSTRLEN + 1 + 8;
    new->addr_text.data = ngx_pcalloc(c->pool, new->addr_text.len);

    if (ngx_open_one_listening_socket(new) == NGX_ERROR) {
        ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "ngx open one listening socket failed");
        return NGX_ERROR;
    }
    if (ngx_event_one_listening_init(new) == NGX_ERROR) {
        ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "ngx event one listening init failed");
        return NGX_ERROR;
    }
    if (getsockname(new->fd, (struct sockaddr *)&addr2, &len)) {
        return NGX_ERROR;
    }

    _port = ntohs(addr2.sin_port);
    ngx_snprintf(new->addr_text.data, new->addr_text.len, "0.0.0.0:%ud", _port);

    return _port;
}

static ngx_int_t
ngx_stream_alg_ftp_resolve_addr(ngx_stream_session_t *s, u_char *addr_info,
        ssize_t size)
{
    u_char addr_str[INET_ADDRSTRLEN + 1] = {0};
    unsigned int ip[4] = {0};
    unsigned int port1, port2;
    struct sockaddr_in *addr;

    if (!ngx_strlchr(addr_info, addr_info + size - 1, ',')) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "format error: , not found");
        return NGX_ERROR;
    }

    ngx_stream_alg_ctx_t *ctx = ngx_stream_get_module_ctx(s, ngx_stream_alg_module);
    if (!ctx) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, NGX_EINVAL, "ngx stream alg module ctx null");
        return NGX_ERROR;
    }

    ngx_stream_upstream_resolved_t *peer = ctx->alg_resolved_peer;
    if (!peer || !peer->sockaddr) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, NGX_EINVAL, "alg resolved peer null");
        return NGX_ERROR;
    }

    addr = (struct sockaddr_in *)peer->sockaddr;
    addr->sin_family = AF_INET;

    ngx_int_t rc = sscanf((const char*)addr_info,
                            "%u,%u,%u,%u,%u,%u",
                            &ip[0], &ip[1], &ip[2], &ip[3],
                            &port1, &port2
                    );

    if (rc != 6) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "format error: address invalid");
        return NGX_ERROR;
    }

    addr->sin_port = htons(port1 * 256 + port2);
    ngx_snprintf(addr_str, INET_ADDRSTRLEN, "%ud.%ud.%ud.%ud", ip[0], ip[1], ip[2], ip[3]);

    addr->sin_addr.s_addr = ngx_inet_addr(addr_str, ngx_strlen(addr_str));
    if (addr->sin_addr.s_addr == INADDR_NONE) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, NGX_EINVAL, "INADDR NONE");
        return NGX_ERROR;
    }

    peer->socklen = sizeof(struct sockaddr_in);
    peer->naddrs = 1;
    peer->port = htons(port1 * 256 + port2);
    peer->no_port = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_stream_alg_process_ftp(ngx_stream_session_t *s, ngx_buf_t *buffer)
{
    ngx_connection_t *c;
    ngx_socket_t fd;
    struct sockaddr_in addr;
    socklen_t len;

    u_char *cmd, *p, *q;
    u_char pasv[] = "227 Entering Passive Mode (";
    u_char port[] = "PORT ";
    ngx_uint_t ftp_mode = 0; // 1-PASV 2-PORT

    u_char addr_str[INET_ADDRSTRLEN + 1] = {0};
    unsigned int ip[4] = {0};

    c = s->connection;
    fd = c->fd;
    len = sizeof(addr);

    ngx_uint_t total_len = buffer->last - buffer->pos;
    if (total_len < 2) {
        ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "format error: truncated");
        return NGX_AGAIN;
    }

    cmd = buffer->pos;
    if (!ngx_strstrn(cmd + total_len - 2, CRLF, 2)) {
        ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "format error: CRLF not found");
        return NGX_AGAIN;
    }

    if (ngx_strstr(cmd, pasv)) {
        ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "FTP passive mode");

        p = ngx_strlchr(cmd, cmd + total_len - 1, '(');
        q = ngx_strlchr(cmd, cmd + total_len - 1, ')');
        if (!p || !q) {
            ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "format error: () not found");
            return NGX_OK;
        }
        ftp_mode = 1;
    }

    if (ngx_strstr(cmd, port)) {
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
        ngx_stream_alg_port_t *alg_port;
        ngx_int_t rv;
        ngx_int_t port = 0;
        ngx_uint_t retry = 0;
        p += 1;
        q -= 1;

        if (ngx_stream_alg_ftp_resolve_addr(s, p, q - p + 1) < 0) {
            ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "format error: ip and port not found");
            return NGX_OK;
        }

        if (ftp_mode == 1) { // PASV mode
            ; // fd = fd
        }
        if (ftp_mode == 2) { // PORT mode
            fd = s->upstream->peer.connection->fd;
        }

        if (getsockname(fd, (struct sockaddr *)&addr, &len)) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "invalid socket fd");
            return NGX_ERROR;
        }

        ngx_inet_ntop(addr.sin_family, (struct sockaddr *)&addr.sin_addr, addr_str, INET_ADDRSTRLEN);

        rv = sscanf((const char *)addr_str, "%u.%u.%u.%u", &ip[0], &ip[1], &ip[2], &ip[3]);
        if(rv != 4 ) {
            ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "invalid address");
            return NGX_OK;
        }

        rv = ngx_stream_alg_get_port(s);
        if (rv != NGX_OK) {
            ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "no data port available");
            return NGX_ERROR;
        }

        alg_port = (ngx_stream_alg_port_t *)(s->alg_port);
        do {
            port = ngx_stream_alg_new_listen(s, alg_port->port);
        } while(port <= 0 && retry++ < 5);

        if (port <= 0) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "create listening port failed");
            return NGX_ERROR;
        }

        ngx_memset(buffer->pos, 0, total_len);

        if (ftp_mode == 1) { // PASV mode
            ngx_snprintf(buffer->pos, 80, "227 Entering Passive Mode \
                    (%ud,%ud,%ud,%ud,%ud,%ud).\r\n",
                    ip[0], ip[1], ip[2], ip[3],
                    port / 256,
                    port % 256
            );
        }

        if (ftp_mode == 2) { // PORT mode
            ngx_snprintf(buffer->pos, 80, "PORT %ud,%ud,%ud,%ud,%ud,%ud\r\n",
                    ip[0], ip[1], ip[2], ip[3],
                    port / 256,
                    port % 256
            );
        }

        buffer->last = buffer->pos + ngx_strlen(buffer->pos);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_stream_alg_process_opcda(ngx_stream_session_t *s, ngx_buf_t *buffer)
{
    ngx_stream_alg_ctx_t *ctx;
    ngx_stream_upstream_resolved_t *peer;
    ngx_stream_alg_port_t *alg_port;
    ngx_socket_t fd;
    struct sockaddr_in addr, *paddr;
    socklen_t addrlen;
    filter_dcom_data_t d;
    ngx_int_t new_port;
    ngx_int_t retry;
    ngx_int_t offset, endian;
    dcom_resp_t type;
    ngx_int_t rv;

    // alg module precheck
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_alg_module);
    if (!ctx) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, NGX_EINVAL, "alg module ctx null");
        return NGX_ERROR;
    }

    peer = ctx->alg_resolved_peer;
    if (!peer || !peer->sockaddr) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, NGX_EINVAL, "alg resolved peer null");
        return NGX_ERROR;
    }

    // dcom protocol precheck
    if (dissect_dcom_precheck(buffer, 0) == NGX_DECLINED) {
        return NGX_OK;
    }

    ngx_memzero(&d, sizeof(filter_dcom_data_t));

    // proxy address
    addrlen = sizeof(struct sockaddr_in);
    ngx_memzero(&addr, addrlen);
    fd = s->connection->fd; // local address
    if (getsockname(fd, (struct sockaddr *)&addr, &addrlen)) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "invalid socket fd");
        return NGX_ERROR;
    }

    ngx_inet_ntop(addr.sin_family,
        (struct sockaddr *)&addr.sin_addr,
        d.iip,
        INET_ADDRSTRLEN
    );

    offset = dissect_dcom_resp_hdr(buffer, 0, &type, &endian);
    if ((type == DCOM_RESP_RESOLVE_OXID2)
        || (type == DCOM_RESP_CREATE_INSTANCE)) {
        /**
         * TODO:
         * if is retrans of dcom response, s->alg_port maybe set last time
         * and listening socket on s->alg_port already open. in this case,
         * we can't free the alg_port.
         */
        rv = ngx_stream_alg_get_port(s);
        if (rv != NGX_OK) {
            return NGX_ERROR;
        }
    }

    alg_port = (ngx_stream_alg_port_t *)(s->alg_port);
    d.iport = alg_port ? alg_port->port : 0;
    buffer->priv = &d;

    NGX_PRINT("dcom proxy ip %s port %d fd %d\n", d.iip, d.iport, fd);

    rv = dissect_dcom_resp(buffer, offset, type, endian, true);
    if (rv == NGX_DECLINED) {
        /**
         * no dynamic port in this packet, all work done.
         */
        goto done;
    }

    // resolved address
    if (!d.oport) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "resolve address failed");
        goto err;
    }

    addrlen = sizeof(struct sockaddr_in);
    ngx_memzero(&addr, addrlen);
    fd = s->upstream->peer.connection->fd; // upstream address
    if (getpeername(fd, (struct sockaddr *)&addr, &addrlen)) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "invalid socket fd");
        goto err;
    }

    paddr = (struct sockaddr_in *)peer->sockaddr;
    *paddr = addr;
    paddr->sin_port = htons(d.oport);

    #if 1
    u_char ip[64] = {0};
    ngx_inet_ntop(addr.sin_family, (struct sockaddr *)&addr.sin_addr, ip, INET_ADDRSTRLEN);
    NGX_PRINT("dcom upstream ip %s port %d\n", ip, d.oport);
    #endif

    // new listening on proxy port for data link
    retry = 0;
    do {
        new_port = ngx_stream_alg_new_listen(s, d.iport);
    } while(new_port <= 0 && retry++ < 5);

    if (new_port <= 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "new listening port failed");
        goto err;
    }

    peer->socklen = sizeof(struct sockaddr_in);
    peer->naddrs = 1;
    peer->port = htons(d.oport);
    peer->no_port = 0;

done:
    return NGX_OK;

err:
    if (alg_port) {
        ngx_stream_alg_free_port(s);
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

    if (pscf->alg_proto == NGX_STREAM_ALG_PROTO_NONE) {
        ; // nothing to do
    }
    if (pscf->alg_proto == NGX_STREAM_ALG_PROTO_FTP) {
        rc = ngx_stream_alg_process_ftp(s, c->buffer);
        if (rc == NGX_ERROR || rc == NGX_AGAIN) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx stream alg process ftp failed");
            return rc;
        }
    }
    if (pscf->alg_proto == NGX_STREAM_ALG_PROTO_OPC_DA) {
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
    ngx_stream_alg_main_conf_t *mcf;
    ngx_int_t rc;
    ngx_connection_t *c;
    ngx_stream_session_t *s;

    c = ev->data;
    s = c->data;

    mcf = ngx_stream_get_module_main_conf(s, ngx_stream_alg_module);
    if (!mcf) {
        ngx_log_error(NGX_LOG_ERR, c->log, NGX_ENOENT, "stream alg module main conf null");
        return;
    }

    rc = ngx_stream_alg_process(ev, NGX_STREAM_ALG_UPSTREAM);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx stream alg process upstream failed");
        return;
    }

    mcf->alg_post_upstream_handler(ev);
    return;
}

static void ngx_stream_alg_downstream_handler(ngx_event_t *ev)
{
    ngx_stream_alg_main_conf_t *mcf;
    ngx_int_t rc;
    ngx_connection_t *c;
    ngx_stream_session_t *s;

    c = ev->data;
    s = c->data;

    mcf = ngx_stream_get_module_main_conf(s, ngx_stream_alg_module);
    if (!mcf) {
        ngx_log_error(NGX_LOG_ERR, c->log, NGX_ENOENT, "stream alg module main conf null");
        return;
    }

    rc = ngx_stream_alg_process(ev, NGX_STREAM_ALG_DOWNSTREAM);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx stream alg process downstream failed");
        return;
    }

    mcf->alg_post_downstream_handler(ev);
    return;
}

static ngx_event_handler_pt ngx_stream_alg_checkout_handler(
        ngx_stream_session_t *s,
        ngx_event_handler_pt alg_post_handler,
        ngx_int_t up_down)
{
    ngx_stream_alg_main_conf_t *mcf;

    mcf = ngx_stream_get_module_main_conf(s,ngx_stream_alg_module);
    if (!mcf) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, NGX_ENOENT, "stream alg module main conf null");
        return NULL;
    }

    if (up_down == NGX_STREAM_ALG_DOWNSTREAM) {
        mcf->alg_post_downstream_handler = alg_post_handler;
        return mcf->alg_downstream_handler;
    } else {
        mcf->alg_post_upstream_handler = alg_post_handler;
        return mcf->alg_upstream_handler;
    }
    return NULL;
}

static void *
ngx_stream_alg_create_main_conf(ngx_conf_t *cf)
{
    ngx_stream_alg_main_conf_t *mcf;

    mcf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_alg_main_conf_t));
    if (!mcf) {
        return NULL;
    }

    mcf->alg_upstream_handler = ngx_stream_alg_upstream_handler;
    mcf->alg_downstream_handler = ngx_stream_alg_downstream_handler;
    mcf->alg_checkout_stream_handler = ngx_stream_alg_checkout_handler;
    return mcf;
}

static ngx_int_t
ngx_stream_alg_handler(ngx_stream_session_t *s)
{
    ngx_stream_proxy_srv_conf_t *pscf;
    ngx_connection_t *c;
    ngx_stream_alg_ctx_t *ctx;
    ngx_listening_t *l;

    c = s->connection;

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);
    if (!pscf) {
        ngx_log_error(NGX_LOG_ERR, c->log, NGX_ENOENT, "stream proxy module srv conf null");
        return NGX_DECLINED;
    }

    if (c->type != SOCK_STREAM) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "connection type error");
        return NGX_DECLINED;
    }

    l = c->listening;

    if (!l->parent_stream_session) { // parent session
        ctx = ngx_stream_get_module_ctx(s, ngx_stream_alg_module);
        if (!ctx) {
            ctx = ngx_pcalloc(c->pool, sizeof(ngx_stream_alg_ctx_t));
            if (!ctx) {
                ngx_log_error(NGX_LOG_ERR, c->log, NGX_ENOMEM, "no memory");
                return NGX_ERROR;
            }

            ctx->alg_resolved_peer = ngx_pcalloc(c->pool, sizeof(ngx_stream_upstream_resolved_t));
            if (!ctx->alg_resolved_peer) {
                ngx_log_error(NGX_LOG_ERR, c->log, NGX_ENOMEM, "no memory");
                return NGX_ERROR;
            }

            ctx->alg_resolved_peer->sockaddr = ngx_pcalloc(c->pool,sizeof(struct sockaddr_in));
            if (!ctx->alg_resolved_peer->sockaddr) {
                ngx_log_error(NGX_LOG_ERR, c->log, NGX_ENOMEM, "no memory");
                return NGX_ERROR;
            }

            ngx_stream_set_ctx(s, ctx, ngx_stream_alg_module);
        }
    }

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

    // dcom_do_test();

    return NGX_OK;
}

static ngx_command_t ngx_stream_alg_commands[] = {
    ngx_null_command
};

static ngx_stream_module_t ngx_stream_alg_module_ctx = {
    NULL,                                /* preconfiguration */
    ngx_stream_alg_postconfiguration,    /* postconfiguration */
    ngx_stream_alg_create_main_conf,     /* create main conf */
    NULL,                                /* init main conf */
    NULL,                                /* create server conf */
    NULL,                                /* merge server conf */
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
