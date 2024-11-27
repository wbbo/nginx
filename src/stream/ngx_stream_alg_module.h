#ifndef _NGX_STREAM_ALG_H_INCLUDED_
#define _NGX_STREAM_ALG_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <nginx.h>

#define NGX_STREAM_ALG_DOWNSTREAM        0
#define NGX_STREAM_ALG_UPSTREAM          1

// web
#define NGX_STREAM_ALG_PROTO_WEB         0
#define NGX_STREAM_ALG_PROTO_HTTP        (NGX_STREAM_ALG_PROTO_WEB + 1)
#define NGX_STREAM_ALG_PROTO_HTTPS       (NGX_STREAM_ALG_PROTO_WEB + 2)
// mail
#define NGX_STREAM_ALG_PROTO_MAIL        10
#define NGX_STREAM_ALG_PROTO_SMTP        (NGX_STREAM_ALG_PROTO_MAIL + 1)
#define NGX_STREAM_ALG_PROTO_IMAP        (NGX_STREAM_ALG_PROTO_MAIL + 2)
#define NGX_STREAM_ALG_PROTO_POP3        (NGX_STREAM_ALG_PROTO_MAIL + 3)
// file
#define NGX_STREAM_ALG_PROTO_FILE        20
#define NGX_STREAM_ALG_PROTO_FTP         (NGX_STREAM_ALG_PROTO_FILE + 1)
#define NGX_STREAM_ALG_PROTO_SMB         (NGX_STREAM_ALG_PROTO_FILE + 2)
#define NGX_STREAM_ALG_PROTO_NFS         (NGX_STREAM_ALG_PROTO_FILE + 3)
// database
#define NGX_STREAM_ALG_PROTO_DATABASE    30
#define NGX_STREAM_ALG_PROTO_MYSQL       (NGX_STREAM_ALG_PROTO_DATABASE + 1)
#define NGX_STREAM_ALG_PROTO_ORACLE      (NGX_STREAM_ALG_PROTO_DATABASE + 2)
#define NGX_STREAM_ALG_PROTO_POSTGRESQL  (NGX_STREAM_ALG_PROTO_DATABASE + 3)
#define NGX_STREAM_ALG_PROTO_SQLSERVER   (NGX_STREAM_ALG_PROTO_DATABASE + 4)
#define NGX_STREAM_ALG_PROTO_DB2         (NGX_STREAM_ALG_PROTO_DATABASE + 5)
#define NGX_STREAM_ALG_PROTO_GBASE       (NGX_STREAM_ALG_PROTO_DATABASE + 6)
#define NGX_STREAM_ALG_PROTO_DM          (NGX_STREAM_ALG_PROTO_DATABASE + 7)
#define NGX_STREAM_ALG_PROTO_KINGBASE    (NGX_STREAM_ALG_PROTO_DATABASE + 8)
// remote access
#define NGX_STREAM_ALG_PROTO_REMOTE_ACCESS 50
#define NGX_STREAM_ALG_PROTO_TELNET      (NGX_STREAM_ALG_PROTO_REMOTE_ACCESS + 1)
#define NGX_STREAM_ALG_PROTO_SSH         (NGX_STREAM_ALG_PROTO_REMOTE_ACCESS + 2)
#define NGX_STREAM_ALG_PROTO_MSRDP       (NGX_STREAM_ALG_PROTO_REMOTE_ACCESS + 3)
// common
#define NGX_STREAM_ALG_PROTO_COMMON      60
#define NGX_STREAM_ALG_PROTO_TCP_NULL    (NGX_STREAM_ALG_PROTO_COMMON + 1)
#define NGX_STREAM_ALG_PROTO_UDP_NULL    (NGX_STREAM_ALG_PROTO_COMMON + 2)
// industrial application
#define NGX_STREAM_ALG_PROTO_INDUSTRIAL  70
#define NGX_STREAM_ALG_PROTO_MODBUS      (NGX_STREAM_ALG_PROTO_INDUSTRIAL + 1)
#define NGX_STREAM_ALG_PROTO_UMAS        (NGX_STREAM_ALG_PROTO_INDUSTRIAL + 2)
#define NGX_STREAM_ALG_PROTO_MQTT        (NGX_STREAM_ALG_PROTO_INDUSTRIAL + 3)
#define NGX_STREAM_ALG_PROTO_DNP3        (NGX_STREAM_ALG_PROTO_INDUSTRIAL + 4)
#define NGX_STREAM_ALG_PROTO_IEC104      (NGX_STREAM_ALG_PROTO_INDUSTRIAL + 5)
#define NGX_STREAM_ALG_PROTO_S7          (NGX_STREAM_ALG_PROTO_INDUSTRIAL + 6)
#define NGX_STREAM_ALG_PROTO_OPC_CLASSIC (NGX_STREAM_ALG_PROTO_INDUSTRIAL + 7)
#define NGX_STREAM_ALG_PROTO_OPC_UA      (NGX_STREAM_ALG_PROTO_INDUSTRIAL + 8)
#define NGX_STREAM_ALG_PROTO_FINS        (NGX_STREAM_ALG_PROTO_INDUSTRIAL + 9)
#define NGX_STREAM_ALG_PROTO_BACNET      (NGX_STREAM_ALG_PROTO_INDUSTRIAL + 10)
#define NGX_STREAM_ALG_PROTO_ETHERNET_IP (NGX_STREAM_ALG_PROTO_INDUSTRIAL + 11)

typedef ngx_event_handler_pt (*ngx_stream_alg_checkout_handler_pt) (
        ngx_stream_session_t *s,
        ngx_event_handler_pt alg_post_handler,
        ngx_int_t up_down
        );

typedef struct {
    ngx_uint_t port;
    ngx_queue_t node;
} ngx_stream_alg_port_t;

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

ngx_stream_alg_port_t *
ngx_stream_alg_get_port(ngx_stream_session_t *s);

void
ngx_stream_alg_free_port(ngx_stream_session_t *s);

#endif /*_NGX_STREAM_ALG_H_INCLUDED_ */
