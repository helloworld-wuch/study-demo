
/*
 * Copyright (C) IDSS-CN, Inc.
 */

#ifndef _FANTAX_INSERT_H_INCLUDED_
#define _FANTAX_INSERT_H_INCLUDED_

#include <ngx_http.h>



typedef struct {
    ngx_array_t   *sub_pairs;  /* array of sub_pair_t */

    

    // ngx_buf_t     *myout;

    ngx_chain_t   *meta;//用来放meta数据
    ngx_chain_t   *last_meta;
    ngx_chain_t   **temp;//标记下，后面解析完成的时候，把meta插入到temp后面

#if 0
    ngx_chain_t   *in;
    /* the line input buffer before substitution */
    ngx_buf_t     *line_in;
    /* the line destination buffer after substitution */
    ngx_buf_t     *line_dst;
    unsigned       last;

    ngx_buf_t*     enc_buf;
#endif

    /* point to the last output chain's next chain */
    ngx_chain_t  **last_out;
    /* the last output buffer */
    ngx_buf_t     *out_buf;
    ngx_chain_t   *out;

    ngx_int_t      bufs;

    ngx_chain_t   *busy;
    /* the freed chain buffers. */
    ngx_chain_t   *free;

    int            start_pos;
    
    int            form_id;
    int            tag_insert_flag;
    ngx_str_t      charset;
    u_char        *scan_begin,*scan_end;
    int            intert_js_once;
    int            gumbo_insert;
    int            has_note;
    ngx_int_t      nflag;
    ngx_int_t      nDocOffset;
    ngx_int_t      nHTMLOffset;
    ngx_int_t      nHEADOffset;
    ngx_int_t      nMETAOffset;
    ngx_int_t      nBODYOffset;
    ngx_int_t      nSCRIPTOffset;
    ngx_str_t      event_id;
    ngx_str_t      response_body;
    ngx_flag_t     from_mobile;

    ngx_str_t      time_id;        /* constant for a request ..init in init_ctx()*/
    u_char         *tempbuf;       // size=2048 a temp var.. just we dont want alloc this mem again and agin
    size_t         tempbuf_size;
} html_ctx_t;

#define IDSS_MAX_GREP_WORDS 32767

static ngx_str_t ngx_http_dom_comment       = ngx_string("<!--");
static ngx_str_t ngx_http_dom_comment_end   = ngx_string("-->");
static ngx_str_t ngx_http_dom_document      = ngx_string("<!doctype");
static ngx_str_t ngx_http_dom_html          = ngx_string("<html");
static ngx_str_t ngx_http_dom_head          = ngx_string("<head");
static ngx_str_t ngx_http_dom_meta          = ngx_string("<meta");
static ngx_str_t ngx_http_dom_body          = ngx_string("<body");
static ngx_str_t ngx_http_dom_script        = ngx_string("<script");
static ngx_str_t input_template_start       = ngx_string("<meta name='idss' id='idss-");
static ngx_str_t input_template_mid         = ngx_string("'><script life='remove'>y4Kdecode('");
static ngx_str_t input_template_end         = ngx_string("')</script>");

ngx_int_t ft_html_insert_js(ngx_http_request_t *r);


#endif
