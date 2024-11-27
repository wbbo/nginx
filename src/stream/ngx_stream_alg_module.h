#ifndef _NGX_STREAM_ALG_H_INCLUDED_
#define _NGX_STREAM_ALG_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <nginx.h>

#define NGX_STREAM_ALG_DOWNSTREAM    0
#define NGX_STREAM_ALG_UPSTREAM      1

#define NGX_STREAM_ALG_PROTO_UNKNOWN 0
#define NGX_STREAM_ALG_PROTO_FTP     1
#define NGX_STREAM_ALG_PROTO_OPC_DA  2

typedef ngx_event_handler_pt (*ngx_stream_alg_checkout_handler_pt) (
        ngx_stream_session_t *s,
        ngx_event_handler_pt alg_post_handler,
        ngx_int_t up_down
        );

typedef struct {
    ngx_uint_t alg_proto;
} ngx_stream_alg_srv_conf_t;

typedef struct {
    ngx_event_handler_pt alg_upstream_handler;
    ngx_event_handler_pt alg_downstream_handler;
    ngx_event_handler_pt alg_post_upstream_handler;
    ngx_event_handler_pt alg_post_downstream_handler;
    ngx_stream_alg_checkout_handler_pt alg_checkout_stream_handler;
} ngx_stream_alg_main_conf_t;

typedef struct {
    ngx_stream_upstream_resolved_t *alg_resolved_peer;
} ngx_stream_alg_ctx_t;

extern ngx_module_t ngx_stream_alg_module;

#endif /*_NGX_STREAM_ALG_H_INCLUDED_ */
