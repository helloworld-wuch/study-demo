
/*
 * Copyright (C) IDSS-CN, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <fantax.h>
#include <txn.h>
#include <public/utils/utils.h>
#include "dom_encrypt.h"
#include "websec_module.h"
#include "mobile_safe.h"
#include "arg_encrypt.h"
#include "insert.h"

static ngx_int_t
denc_init_ctx(ngx_http_request_t *r)
{
    denc_ctx_t          *ctx;
    transaction_t       *t = txn_from_req(r);
    char *buf;
    ctx = ngx_pcalloc(r->pool, sizeof(denc_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    txn_set_module_ctx(t, ctx, dom_encrypt_module);

    buf = ngx_palloc(r->pool, 30);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    str_itoa(r->start_msec & 0xFFF, buf, 10);
    ctx->time_id.data = (u_char *)buf;
    ctx->time_id.len = strlen(buf);

    ctx->tempbuf = ngx_pcalloc(r->pool, 2048);
    if (ctx->tempbuf == NULL) {
        return NGX_ERROR;
    }
    ctx->tempbuf_size = 2048;

    ctx->event_id = genRandomString(8, r->pool);
    if (!ctx->event_id.data) {
        return NGX_ERROR;
    }

    ctx->last_out = &ctx->out;
	ctx->out_buf = NULL;
    return NGX_OK;
}


#if 1
bool ngx_check_html2(denc_ctx_t* sub_ctx, ngx_http_request_t *r, const char *body, ngx_int_t body_len)
{
    u_char ch, look;

    if (NULL == body || body_len < TREAT_TXT_LIMIT_MINLEN) {
        return false;
    }
    
    ngx_http_dom_ctx_t *ctx;
    ctx = ngx_palloc(r->pool, sizeof(ngx_http_dom_ctx_t));
    if (ctx == NULL) {
        return false;
    }
    
    if (body_len > IDSS_MAX_GREP_WORDS) {
        body_len = IDSS_MAX_GREP_WORDS;
    }
    
    ngx_int_t nOffset = 0;
    sub_ctx->nflag = 0;
    sub_ctx->nDocOffset =  IDSS_MAX_GREP_WORDS + 1;
    sub_ctx->nHTMLOffset = IDSS_MAX_GREP_WORDS + 1;
    sub_ctx->nHEADOffset = IDSS_MAX_GREP_WORDS + 1;
    sub_ctx->nMETAOffset = IDSS_MAX_GREP_WORDS + 1;
    sub_ctx->nBODYOffset = IDSS_MAX_GREP_WORDS + 1;
    sub_ctx->nSCRIPTOffset = IDSS_MAX_GREP_WORDS + 1;

    ctx->state = 0;
    ctx->saved_comment = 0;

    for (nOffset=0; nOffset < body_len && (sub_ctx->nflag & NGX_HTTP_DOM_TAG_BODY) == 0; nOffset++) {
        ch = ngx_tolower(*(body + nOffset));
        
        switch (ctx->state) {
                
            case dom_state_text:
                switch (ch) {
                    case '\r':
                    case '\n':
                    case '\t':
                    case ' ':
                        continue;
                    case '<':
                        ctx->state = dom_state_tag;
                        continue;
                    default:
                        break;
                }
                break;
                
            case dom_state_tag:
                switch (ch) {
                    case '\r':
                    case '\n':
                    case '\t':
                    case ' ':
                        break;
                    case '!':
                        ctx->state = dom_state_comment_begin;
                        continue;
                    case 'h':
                        ctx->state = dom_state_tag_h; /* </head> or </html> */
                        break;
                    case 'm':
                        ctx->state = dom_state_tag_meta_begin;
                        ctx->looked = 2;        /* </meta> */
                        break;
                    case 'b':
                        if (sub_ctx->nDocOffset < nOffset && sub_ctx->nHTMLOffset < nOffset && sub_ctx->nHEADOffset < nOffset && sub_ctx->nMETAOffset < nOffset && sub_ctx->nSCRIPTOffset < nOffset) {
                            break;
                        }
                        ctx->state = dom_state_tag_body_begin;
                        ctx->looked = 2;        /* </body> */
                        break;
                    case 's':
                        ctx->state = dom_state_tag_script_begin;
                        ctx->looked = 2;        /* </script> */
                        break;
                    case '<':
                        break;
                    default:
                        ctx->state = dom_state_text;
                        break;
                }
                
                break;
                
            case dom_state_tag_h:
                switch (ch) {
                    case 'e':
                        ctx->state = dom_state_tag_head_begin;
                        ctx->looked = 3;    /* </head> */
                        break;
                    case 't':
                        ctx->state = dom_state_tag_html_begin;
                        ctx->looked = 3;    /* </html> */
                        break;
                    default:
                        ctx->state = dom_state_text;
                        break;
                }
                break;
    
            case dom_state_tag_html_begin:
                look = ngx_http_dom_html.data[ctx->looked++];
                
                if (ch == look) {
                    if (ctx->looked == ngx_http_dom_html.len) {
                        ctx->state = dom_state_tag_html_end;
                    }
                    
                    continue;
                }
                
                ctx->state = dom_state_text;

                break;

            case dom_state_tag_html_end:
                switch (ch) {
                    case ' ':
                    case '\r':
                    case '\n':
                    case '>':
                        if ((sub_ctx->nflag & NGX_HTTP_DOM_TAG_HTML) == 0) {
                            sub_ctx->nflag |= NGX_HTTP_DOM_TAG_HTML;
                            sub_ctx->nHTMLOffset = nOffset - ngx_http_dom_html.len;
                        }
                        ctx->looked = 0;
                    default:
                        ctx->state = dom_state_text;
                        break;
                }
                break;
                
            case dom_state_tag_head_begin:
                look = ngx_http_dom_head.data[ctx->looked++];
                
                if (ch == look) {
                    if (ctx->looked == ngx_http_dom_head.len) {
                        ctx->state = dom_state_tag_head_end;
                    }
                    
                    continue;
                }
                
                ctx->state = dom_state_text;
                
                break;

            case dom_state_tag_head_end:
                switch (ch) {
                    case ' ':
                    case '\r':
                    case '\n':
                    case '>':
                        if ((sub_ctx->nflag & NGX_HTTP_DOM_TAG_HEAD) == 0) {
                            sub_ctx->nflag |= NGX_HTTP_DOM_TAG_HEAD;
                            sub_ctx->nHEADOffset = nOffset - ngx_http_dom_head.len;
                        }
                        ctx->looked = 0;
                    default:
                        ctx->state = dom_state_text;
                        break;
                }
                break;
                
            case dom_state_comment_begin:
                switch (ch) {
                    case 'd':
                        ctx->state = dom_state_comment_document_begin;
                        ctx->looked = 3;    /* <!document> */
                        break;
                    case '-':
                        ctx->state = dom_state_comment_hack_begin;
                        ctx->looked = 3;    /* <!-- */
                        break;
                    default:
                        ctx->state = dom_state_text;
                        break;
                }
                
                break;
                
            case dom_state_comment_document_begin:
                look = ngx_http_dom_document.data[ctx->looked++];
                
                if (ch == look) {
                    if (ctx->looked == ngx_http_dom_document.len) {
                        ctx->state = dom_state_comment_document_end;
                    }
                    
                    continue;
                }
                
                ctx->state = dom_state_text;
                
                break;
                
            case dom_state_comment_document_end:
                switch (ch) {
                    case ' ':
                    case '\r':
                    case '\n':
                    case '>':
                        if ((sub_ctx->nflag & NGX_HTTP_DOM_TAG_DOCUMENT) == 0) {
                            sub_ctx->nflag |= NGX_HTTP_DOM_TAG_DOCUMENT;
                            sub_ctx->nDocOffset = nOffset - ngx_http_dom_document.len;
                        }
                        ctx->looked = 0;
                    default:
                        ctx->state = dom_state_text;
                        break;
                }
                break;
                
            case dom_state_comment_hack_begin:
                look = ngx_http_dom_comment.data[ctx->looked++];
                
                if (ch == look) {
                    if (ctx->looked == ngx_http_dom_comment.len) { /* !-- */
                        ctx->state = dom_state_comment_hack_end;
                        ctx->looked = 0;
                    }
                    
                    continue;
                }
                
                ctx->state = dom_state_text;
                
                break;
                
            case dom_state_comment_hack_end:
                look = ngx_http_dom_comment_end.data[ctx->looked++];
                
                if (ch == look) {
                    if (ctx->looked == ngx_http_dom_comment_end.len) { /* !-- */
                        ctx->state = dom_state_text;
                        ctx->looked = 0;
                    }
                    
                    continue;
                }
                
                ctx->looked = 0;
                break;
            
            case dom_state_tag_meta_begin:
                look = ngx_http_dom_meta.data[ctx->looked++];
                
                if (ch == look) {
                    if (ctx->looked == ngx_http_dom_meta.len) {
                        ctx->state = dom_state_tag_meta_end;
                    }
                    
                    continue;
                }
                
                ctx->state = dom_state_text;

                break;
                
            case dom_state_tag_meta_end:
                switch (ch) {
                    case ' ':
                    case '\r':
                    case '\n':
                    case '>':
                        if ((sub_ctx->nflag & NGX_HTTP_DOM_TAG_META) == 0) {
                            sub_ctx->nflag |= NGX_HTTP_DOM_TAG_META;
                            sub_ctx->nMETAOffset = nOffset - ngx_http_dom_meta.len;
                        }
                        ctx->looked = 0;
                    default:
                        ctx->state = dom_state_text;
                        break;
                }
                break;
                
            case dom_state_tag_body_begin:
                look = ngx_http_dom_body.data[ctx->looked++];
                
                if (ch == look) {
                    if (ctx->looked == ngx_http_dom_body.len) {
                        ctx->state = dom_state_tag_body_end;
                        ctx->looked = 0;
                    }
                    
                    continue;
                }
                
                ctx->state = dom_state_text;

                break;
                
            case dom_state_tag_body_end:
                switch (ch) {
                    case '\'':
                        ctx->saved_comment ^= 1;
                        break;
                    case '"':
                        ctx->saved_comment ^= 2;
                        break;
                    case '>':
                        if (ctx->saved_comment == 0) {
                            ctx->state = dom_state_text;
                            if ((sub_ctx->nflag & NGX_HTTP_DOM_TAG_BODY) == 0) {
                                sub_ctx->nflag |= NGX_HTTP_DOM_TAG_BODY;
                                sub_ctx->nBODYOffset = nOffset;
                            }
                        }
                        break;
                    default:
                        break;
                }
                break;
                
            case dom_state_tag_script_begin:
                look = ngx_http_dom_script.data[ctx->looked++];
                
                if (ch == look) {
                    if (ctx->looked == ngx_http_dom_script.len) {
                        ctx->state = dom_state_tag_script_end;
                    }
                    
                    continue;
                }
                
                ctx->state = dom_state_text;

                break;
                
            case dom_state_tag_script_end:
                switch (ch) {
                    case ' ':
                    case '\r':
                    case '\n':
                    case '>':
                        if ((sub_ctx->nflag & NGX_HTTP_DOM_TAG_SCRIPT) == 0) {
                            sub_ctx->nflag |= NGX_HTTP_DOM_TAG_SCRIPT;
                            sub_ctx->nSCRIPTOffset = nOffset - ngx_http_dom_script.len;
                        }
                        ctx->looked = 0;
                    default:
                        ctx->state = dom_state_text;
                        break;
                }
                break;
                
            default:
                break;
        }
    }
    
    return sub_ctx->nflag != 0;
}
#endif


static ngx_str_t
ngx_chain2str(ngx_chain_t *chain, ngx_pool_t *pool) {
    u_char       *p;
    size_t        len;
    ngx_buf_t    *buf;
    ngx_chain_t  *cl;
    ngx_str_t    str;


    ngx_str_null(&str);
    if (chain == NULL)
    {
        return str;
    }

    cl = chain;
    buf = cl->buf;

    if (cl->next == NULL) {
        str.len = buf->last - buf->pos;
        str.data = buf->pos;
        return str;
    }

    len = buf->last - buf->pos;
    cl = cl->next;

    for ( /* void */ ; cl; cl = cl->next) {
        buf = cl->buf;
        len += buf->last - buf->pos;
    }

    p = ngx_pnalloc(pool, len);
    if (p == NULL) {
        return str;
    }

    str.data = p;
    cl = chain;

    for ( /* void */ ; cl; cl = cl->next) {
        buf = cl->buf;
        p = ngx_cpymem(p, buf->pos, buf->last - buf->pos);
    }

    str.len = len;
    return str;
}

static ngx_int_t
denc_get_chain_buf(ngx_http_request_t *r,
    denc_ctx_t *ctx)
{
    ngx_chain_t      *temp;
    denc_loc_conf_t  *dlcf;
    
    transaction_t    *t = txn_from_req(r);

    dlcf = txn_get_module_loc_conf(t, &dom_encrypt_module);

    if (ctx->free) {
        temp = ctx->free;
        ctx->free = ctx->free->next;

    } else {
        temp = ngx_alloc_chain_link(r->pool);
        if (temp == NULL) {
            return NGX_ERROR;
        }

        temp->buf = ngx_create_temp_buf(r->pool, dlcf->bufs.size);
        if (temp->buf == NULL) {
            return NGX_ERROR;
        }

        temp->buf->tag = (ngx_buf_tag_t)&dom_encrypt_module;
        temp->buf->recycled = 1;

        /* TODO: limit the buffer number */
        ctx->bufs++;
    }

    temp->next = NULL;

    ctx->out_buf = temp->buf;
    *ctx->last_out = temp;
    ctx->last_out = &temp->next;

    return NGX_OK;
}

//append buf to outbuf 
static ngx_int_t
denc_out_chain_append(ngx_http_request_t *r,
    denc_ctx_t *ctx, ngx_buf_t *b)
{
    size_t       len, capcity;

    if (b == NULL || b->pos == NULL || ngx_buf_size(b) == 0) {
        return NGX_OK;
    }
#if 0
    printf("%.*s", b->last - b->pos, b->pos);
#endif
    if (ctx->out_buf == NULL) {
        if (denc_get_chain_buf(r, ctx) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    while (1) {

        len = (size_t)ngx_buf_size(b);
        if (len == 0) {
            break;
        }

        capcity = ctx->out_buf->end - ctx->out_buf->last;

        if (len <= capcity) {
            ctx->out_buf->last = ngx_copy(ctx->out_buf->last, b->pos, len);
            b->pos += len;
            break;

        } else {
            ctx->out_buf->last = ngx_copy(ctx->out_buf->last,
                b->pos, capcity);
        }

        b->pos += capcity;

        /* get more buffers */
        if (denc_get_chain_buf(r, ctx) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static inline ngx_int_t
denc_out_chain_append_str2(ngx_http_request_t *r,
    denc_ctx_t *ctx, ngx_str_t *value) {
    ngx_buf_t buf;

    buf.memory = 1;
    buf.pos = value->data;
    buf.last = value->data + value->len;

    return denc_out_chain_append(r, ctx, &buf);
}

ngx_int_t 
denc_aes_enc_and_base64_str2(transaction_t *t, ngx_int_t aes_key_len, ngx_str_t *data, ngx_str_t *out) {
    ngx_http_request_t *r;
    ngx_str_t ciphertext, key, value;
    r = t->source;


    if (out == NULL) {
        return NGX_ERROR;
    }

    ciphertext.len = AES_ENCODE_LEN(data->len);
    ciphertext.data = ngx_pcalloc(r->pool, ciphertext.len);
    if (ciphertext.data == NULL) {
        return NGX_ERROR;
    }

    key = genRandomString(aes_key_len, r->pool);
    if (key.len == 0) {
        return NGX_ERROR;
    }

    Aes_encrypt(data, &ciphertext, key.data);

    /*out formate is 16 byte key +  base64 data */
    out->len = ngx_base64_encoded_length(ciphertext.len) + aes_key_len;
    out->data = ngx_palloc(r->pool, out->len);
    if (out->data == NULL) {
        return NGX_ERROR;
    }
    value = *out;

    //copy 16 byte key
    memcpy(value.data, key.data, key.len);

    value.data += 16;
    value.len -= 16;

    //compute and copy base64 data
    ngx_encode_base64(&value, &ciphertext);

    return NGX_OK;
}

ngx_int_t js_res_get2(denc_loc_conf_t *dlcf, ngx_http_request_t *r, ngx_int_t phase)
{
    //phase: 0阶段为466
#if (FT_HTTP_AJAX)
    arg_encrypt_conf_t     *aecf;
    aecf = txn_get_module_loc_conf(txn_from_req(r), &arg_encrypt_module);
#endif
    
#if (FT_HTTP_MOBILE_SAFE)
    mobile_safe_loc_conf_t *mscf;
    mscf = txn_get_module_loc_conf(txn_from_req(r), &mobile_safe_module);
#endif

    ngx_int_t js_res = 0;

#if (FT_HTTP_AJAX)
    if (aecf->ajax_req_enc){
        js_res |= NGX_JS_AJAX;
    }
    if (aecf->form_req_enc){
        js_res |= NGX_JS_FORM;
    }
    if (aecf->mobile_req_enc){
        js_res |= NGX_APP_REQ_ENC;
    }
    if (aecf->mobile_resp_enc){
        js_res |= NGX_APP_RESP_ENC;
    }
#endif
    if (dlcf->ie11_activex) {
        js_res |= NGX_JS_IE11;
    }
    if (dlcf->xhs_eshare) {
        js_res |= NGX_JS_SHARE;
    }
    if (dlcf->frontend_guard) {
        js_res |= NGX_JS_FRONT;
    }
    if (dlcf->iframe_guard) {
        js_res |= NGX_JS_IFRAME;
    }
    if (dlcf->keyboard_guard) {
        js_res |= NGX_JS_KEYBOARD;
    }
    if (dlcf->wechat_guard) {
        js_res |= NGX_JS_WECHAT;
    }
    if (dlcf->dtalk_guard) {
        js_res |= NGX_JS_DTALK;
    }
    if (dlcf->debug_protection) {
        js_res |= NGX_JS_DEBUG;
    }
    switch (dlcf->social_traceability) {
        case 1:
            // 完全开启
            js_res |= NGX_SOCIAL_TRACE;
            break;
        case 2:
            // 随机开启
            if (genRandoms(0, 1, 1, 2) == 1) {
                js_res |= NGX_SOCIAL_TRACE;
            }
            break;
        case 3:
            if (phase == 0) {
                js_res |= NGX_SOCIAL_TRACE;
            }
            break;
        case 4:
            if (r->idss_action == 1 && phase != 0) {
                js_res |= NGX_SOCIAL_TRACE;
            }
            break;
        case 0:
        default:
            break;
    }
    if (r->isTraceAbility == 1) {
        js_res |= NGX_SOCIAL_TRACE;
    }
    if (dlcf->share_data) {
        js_res |= NGX_SHARE_DATA;
    }
    if (dlcf->js_interval){
        js_res |= NGX_JS_INTERVAL;
    }
#if (FT_HTTP_MOBILE_SAFE)
    if (mscf->mobile_api_id){
        js_res |= NGX_APP_API_ID;
    }
    if (mscf->mobile_info_collect){
        js_res |= NGX_APP_INFO_COLLECT;
    }
    if (mscf->mobile_force_ssl){
        js_res |= NGX_APP_FORCE_SSL;
    }
    if (mscf->mobile_log_data){
        js_res |= NGX_APP_LOG_DATA;
    }
#endif

    return js_res;
}

ngx_str_t rule_res_get2(ngx_http_request_t *r, ngx_int_t phase)
{
    ngx_str_t                        hijack2;
    denc_loc_conf_t                 *dlcf;
    transaction_t                   *t = txn_from_req(r);

#if (NGX_HTTP_TOKEN)
    limit_token_conf_t     *lrcf;
#endif

    ngx_str_null(&hijack2);
    ngx_int_t                        js_res = 0;

    dlcf = txn_get_module_loc_conf(t, &dom_encrypt_module);
    
#if (NGX_HTTP_TOKEN)
    lrcf = txn_get_module_loc_conf(t, &limit_token_module);
#endif

#if (FT_HTTP_MOBILE_SAFE)
    mobile_safe_loc_conf_t *mscf;
    mscf = txn_get_module_loc_conf(t, &mobile_safe_module);
#endif

    js_res = js_res_get2(dlcf, r, phase);
    
    ngx_str_t config_str;
    config_str.data = ngx_pnalloc(r->pool, 1024);
    
    if (config_str.data == NULL) {
        return hijack2;
    }
    
    denc_ctx_t       *ctx;
    ctx = txn_get_module_ctx(t, dom_encrypt_module);

    ngx_int_t cookie_expire, cookie_freq, reserve_check, protect_mode;
    ngx_int_t mobile_info_collect_type, mobile_collect_interval, mobile_max_collect_items, mobile_max_collect_size, mobile_info_collect_items;
    ngx_str_t reserve_host_list, mobile_cookie_name, cookie_name, mobile_info_collect_url;
    
    protect_mode = txn_get_protect_mode(t);
    
#if (FT_HTTP_MOBILE_SAFE)
    //mobile about
    mobile_info_collect_url = mscf->mobile_info_collect_url;
    mobile_info_collect_type = mscf->mobile_info_collect_type;
    mobile_collect_interval = mscf->mobile_collect_interval;
    mobile_max_collect_items = mscf->mobile_max_collect_items;
    mobile_max_collect_size = mscf->mobile_max_collect_size;
    mobile_info_collect_items = mscf->mobile_info_collect_items;
#else
    mobile_info_collect_type = 0;
    mobile_collect_interval = 0;
    mobile_max_collect_items = 0;
    mobile_max_collect_size = 0;
    mobile_info_collect_items = 0;
    
    ngx_str_set(&mobile_info_collect_url, "");
#endif

#if (NGX_HTTP_TOKEN)
    cookie_expire = lrcf->cookie_expire;
    cookie_freq = lrcf->cookie_freq;
    reserve_check = lrcf->reserve_check;
    
    reserve_host_list = lrcf->reserve_host;
    mobile_cookie_name = lrcf->mobile_cookie_name;
    cookie_name = lrcf->cookie_name;
#else
    cookie_expire = 1;
    cookie_freq = 1;
    reserve_check = 1;

    ngx_str_set(&reserve_host_list, "");
    ngx_str_set(&mobile_cookie_name, "");
    ngx_str_set(&cookie_name, "");
#endif
    
    if (r->ismobile == 1) {
        if (ctx != NULL && ctx->from_mobile == 1) {
            protect_mode = txn_get_protect_mode(t);
        }
        
        config_str.len = ngx_sprintf(config_str.data, "%d,%d,%d,%d,%V,%d,%V,%d,%V,%d,%d,%d,%d,%d", js_res * cookie_expire % cookie_freq, js_res, cookie_expire, cookie_freq, &mobile_cookie_name, reserve_check, &reserve_host_list, protect_mode, &mobile_info_collect_url, mobile_info_collect_type, mobile_collect_interval, mobile_max_collect_items, mobile_max_collect_size, mobile_info_collect_items) - config_str.data;
    } else {
        config_str.len = ngx_sprintf(config_str.data, "%d`%d`%d`%d`%V`%d`%V`%d`%V`%d`%d`%d`%d`%d", js_res * cookie_expire % cookie_freq, js_res, cookie_expire, cookie_freq, &cookie_name, reserve_check, &reserve_host_list, protect_mode, &mobile_info_collect_url, mobile_info_collect_type, mobile_collect_interval, mobile_max_collect_items, mobile_max_collect_size, mobile_info_collect_items) - config_str.data;
    }

    if (denc_aes_enc_and_base64_str2(t, 16, &config_str, &hijack2) == NGX_ERROR) {
        //hijack2: ngx_str_null(&hijack2);
        return hijack2;
    }
    
    printf("rule res get: %.*s\n", hijack2.len, hijack2.data);
    return hijack2;
}

/**FIXME: remove type*/
ngx_int_t ngx_http_script_buf2(denc_loc_conf_t *dlcf, denc_ctx_t* ctx, ngx_http_request_t *r, u_char* tempbuf, ngx_str_t *time_id, ngx_int_t type) {
    // type: 0 不需要混淆节点 1 需要混淆节点
    ngx_int_t                tempbuf_len = 0;
    denc_srv_conf_t         *scf;
    
    transaction_t           *t = txn_from_req(r);
    
    scf = txn_get_module_srv_conf(t, &dom_encrypt_module);
    
    ngx_str_t hijack2;
    hijack2 = rule_res_get2(r, 1);
    
    //ngx_uint_t         size;
    ngx_str_t          *info;
    ngx_str_t          used;
    ngx_str_t          detail;
    u_char      *watermark_tmp, *watermark_end;
    u_char      *watermark_encode;
    u_char      *detail_encode;
    uintptr_t   n = 0;
    ngx_int_t   watermark_len, detail_len;

    //size = ngx_cycle->license_infos.nelts;
    info = ngx_cycle->license_infos.elts;
    
    switch (ngx_atoi(info[5].data, info[5].len)) {
        case 1:
            ngx_str_set(&used, "开发");
            break;

        case 2:
            ngx_str_set(&used, "测试");
            break;
            
        case 3:
            ngx_str_set(&used, "演示");
            break;
            
        case 4:
            ngx_str_set(&used, "POC");
            break;
            
        case 5:
            ngx_str_set(&used, "正式");
            break;
        default:
            ngx_str_set(&used, "开发");
            break;
    }
    
    if (ngx_atoi(info[5].data, info[5].len) != 5 && ngx_atoi(info[5].data, info[5].len) != 4) {
        watermark_tmp = ngx_pnalloc(r->pool, 92 + 
                                             used.len + 
                                             info[4].len + 
                                             1 //'\0'
                                             );
        if (watermark_tmp == NULL) {
            return NGX_ERROR;
        }
        
        watermark_end = ngx_snprintf(watermark_tmp, 92 + used.len + info[4].len, \
        "800px|600px|center|middle|20px Microsoft Yahei|rgba(184, 184, 184, 0.4)|仅限%V%V使用|30|1000", \
        &info[4], &used);
        
        watermark_len = watermark_end - watermark_tmp;
        watermark_tmp[watermark_len] = 0;

        n = ngx_escape_uri(NULL, watermark_tmp, watermark_len, NGX_ESCAPE_URI_COMPONENT);

        watermark_encode = ngx_pnalloc(r->pool, watermark_len + 
                                                n * 2 + 
                                                1 // '\0'
                                                );
        if (watermark_encode == NULL) {
            return NGX_ERROR;
        }
        (void) ngx_escape_uri(watermark_encode, watermark_tmp, watermark_len, NGX_ESCAPE_URI_COMPONENT);
        watermark_encode[watermark_len + n * 2] = 0;
        
        dlcf->watermark.data = watermark_encode;
        dlcf->watermark.len = watermark_len + n * 2;
    }

    ngx_str_t hijack;

    if (denc_aes_enc_and_base64_str2(t, 16, &dlcf->watermark, &hijack) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_int_t isWechat = genRandoms(40, 125, 1, dlcf->wechat_guard);

#if (NGX_DEBUG)
    
    tempbuf_len = ngx_sprintf(tempbuf, "<script src='%V/idss/fao4eEH7YG.js' x='b'></script><meta id='4t0V2kPn' content='%c%V'/><meta id='hKGx4Fvo' content='%V'/>\
    <script src = '%V/idss/E0hh1zI6/' x='g'></script>",  \
    &scf->javascript_prefix, isWechat, &hijack2, &hijack, &scf->javascript_prefix) - tempbuf;


#else
    ngx_int_t split_len = 6;
    ngx_str_t time = get_encrypt_time(r->pool);
    
    tempbuf_len = ngx_sprintf(tempbuf, "<script src='%V/idss/fao4eEH7YG.js?%*s=%*s' x='b'></script><meta id='4t0V2kPn' content='%c%V'/><meta id='hKGx4Fvo' content='%V'/><script src = '%V/idss/E0hh1zI6/?%*s=%*s&%*s=%*s' x='g'></script>",  \
    &scf->javascript_prefix, split_len, time.data, split_len, time.data+split_len, isWechat, &hijack2, &hijack, &scf->javascript_prefix, split_len, \
    time.data + split_len*2, split_len, time.data+split_len*3, split_len, time.data+split_len*4, time.len-split_len*5-2, time.data+split_len*5) - tempbuf;
#endif
    
    if (r->idss_action == 1) {
        detail_encode = r->detail.data;
        detail_len = r->detail.len;
    
        n = ngx_escape_html(NULL, r->detail.data, r->detail.len);

        if (n) {
            detail_encode = ngx_pnalloc(r->pool, r->detail.len + n);
            if (detail_encode == NULL) {
                //if NULL, use origin text
            } else {
                (void) ngx_escape_html(detail_encode, r->detail.data, r->detail.len);
                detail_len = r->detail.len + n;
            }
        }
        
        detail.data = detail_encode;
        detail.len = detail_len;
        
        ngx_str_t from_ip = ngx_get_client_ip(r);
            
        // 插入JS
        tempbuf_len = ngx_sprintf(tempbuf+tempbuf_len, "<script>var title = \"%V\";var body = \"%V\";var ip = \"%V\";var payload = \"%V\";var eveid = \"%V\";var source_no = %d;</script>", \
        &dlcf->exception_title, &dlcf->exception_body, &from_ip, &detail, &ctx->event_id, dlcf->exception_elem) - tempbuf;
    }

    if (r->thirdJsName.len > 0) {
        tempbuf_len = ngx_sprintf(tempbuf+tempbuf_len, "<script src='%V/%V'></script>", &scf->javascript_prefix, &r->thirdJsName) - tempbuf;
    }
    
    if (type == 1) {
        tempbuf_len = ngx_sprintf(tempbuf+tempbuf_len, "<meta id='data-ts-%V' content=\"", time_id) - tempbuf;
    }

    return tempbuf_len;
}


//only inert once time 
ngx_int_t ngx_http_insert_js2(ngx_http_request_t *r, denc_ctx_t* ctx) {
    ngx_int_t            tempbuf_len = 0;
    denc_loc_conf_t     *dlcf;
    transaction_t       *t = txn_from_req(r);
    ngx_str_t            value;


    
    dlcf = txn_get_module_loc_conf(t, &dom_encrypt_module);
    
    tempbuf_len = ngx_http_script_buf2(dlcf, ctx, r, ctx->tempbuf, NULL, 0);
    
    value.data = ctx->tempbuf;
    value.len = tempbuf_len;

    denc_out_chain_append_str2(r, ctx, &value);
    

    return NGX_OK;
}

void ngx_http_insert_js_page_before2(ngx_http_request_t *r, denc_ctx_t* ctx, ngx_int_t pos, ngx_str_t *body) {
    
    ngx_str_t value;

    value.data = body->data;
    value.len = pos;

    denc_out_chain_append_str2(r, ctx, &value);
    //插入js
    ngx_http_insert_js2(r, ctx);


    value.data = body->data + pos;
    value.len = body->len - pos;
    denc_out_chain_append_str2(r, ctx, &value);

    ctx->intert_js_once = 1;
    return ;
}

void denc_flush_scan_buf2(ngx_http_request_t *r, denc_ctx_t* ctx)
{
    ngx_str_t value;
    if (ctx->scan_begin > ctx->scan_end) {
        ctx->scan_begin = ctx->scan_end;
        return;
    }
    
    if (ctx->scan_begin == ctx->scan_end) {
        return;
    }

    value.data = ctx->scan_begin;
    value.len = ctx->scan_end - ctx->scan_begin;
    
    denc_out_chain_append_str2(r, ctx, &value);

    ctx->scan_begin = ctx->scan_end;
}

void ngx_http_parse_charset2(ngx_http_request_t* r, GumboNode* node, denc_ctx_t* ctx)
{
    unsigned int           i;

    for (i = 0; i < node->v.element.attributes.length; i++) {
        GumboAttribute *attr = node->v.element.attributes.data[i];
        if (strcasecmp(attr->name, "charset") == 0) {
            ctx->charset.data = (u_char*)attr->value;
            ctx->charset.len = strlen(attr->value);
            break;
        } else if (strcasecmp(attr->name, "http-equiv") == 0 &&
            strcasecmp(attr->value, "content-type") == 0) {
            if (i < node->v.element.attributes.length - 1) {
                attr = node->v.element.attributes.data[i + 1];
                if (strcasecmp(attr->name, "content") == 0) {
                    char* p = strstr(attr->value, "charset=");
                    if (p != NULL) {
                        ctx->charset.data = (u_char*)p + 8;
                        ctx->charset.len = strlen(p + 8);
                        break;
                    }
                }
            }
        }
    }
}



int ngx_http_replace_tag2(ngx_http_request_t *r, denc_ctx_t* ctx, ngx_str_t *body)
{
    ngx_chain_t              *temp;
    GumboOutput              *output;
    denc_loc_conf_t          *dlcf;
    
    transaction_t            *t = txn_from_req(r);
    ngx_str_t                value;

    dlcf = txn_get_module_loc_conf(t, &dom_encrypt_module);
    ctx->tag_insert_flag = 0;

    ctx->charset = r->headers_out.charset;

    ctx->start_pos = 0;

    temp = ngx_alloc_chain_link(r->pool);
    if (temp == NULL) {
        return NGX_ERROR;
    }
    temp->next = NULL;
    ctx->meta = temp;
    ctx->last_meta = temp;

    ctx->meta->buf = ngx_create_temp_buf(r->pool, 4096);
    if (ctx->meta->buf == NULL) {
        return NGX_ERROR;
    }

    ctx->scan_begin = body->data;

#if (NGX_DEBUG)
    printf("doc nOffset:%d\n", ctx->nDocOffset);
    printf("html nOffset:%d\n", ctx->nHTMLOffset);
    printf("head nOffset:%d\n", ctx->nHEADOffset);
    printf("meta nOffset:%d\n", ctx->nMETAOffset);
    printf("script nOffset:%d\n", ctx->nSCRIPTOffset);
    printf("body nOffset:%d\n", ctx->nBODYOffset);
#endif

    // 没有加密对象,或者只加密AJAX
    if (dlcf == NULL || dlcf->dom_encrypt == NGX_HTTP_DOM_OFF) {
        ngx_int_t nOffset = -1;
        if (ctx->nflag & NGX_HTTP_DOM_TAG_SCRIPT && ctx->nSCRIPTOffset < ctx->nBODYOffset) {
            
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					"[dom_encrypt] use script.");
            
            nOffset = ctx->nSCRIPTOffset;
        } else if (ctx->nflag & NGX_HTTP_DOM_TAG_META && ctx->nMETAOffset < ctx->nBODYOffset) {

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					"[dom_encrypt] use meta.");
            nOffset = ctx->nMETAOffset;

        } else if (ctx->nflag & NGX_HTTP_DOM_TAG_HEAD && ctx->nHEADOffset < ctx->nBODYOffset) {

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					"[dom_encrypt] use head.");
            nOffset = ctx->nHEADOffset;
        } else if (ctx->nflag & NGX_HTTP_DOM_TAG_BODY) {

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					"[dom_encrypt] use body.");
            nOffset = ctx->nBODYOffset;
        } else if (ctx->nflag & NGX_HTTP_DOM_TAG_HTML) {

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					"[dom_encrypt] use html.");
            nOffset = ctx->nHTMLOffset;
        } else if (ctx->nflag & NGX_HTTP_DOM_TAG_DOCUMENT) {

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					"[dom_encrypt] use doc.");
            nOffset = ctx->nDocOffset;
        } else if (dlcf->force_mode == 1) {
            nOffset = 0;
        }
        
        if (nOffset == -1) {
            //some error ...
            return NGX_ERROR;
        }

        ngx_http_insert_js_page_before2(r, ctx, nOffset, body);
        
        return NGX_OK;
    }

    ctx->gumbo_insert = 0; /* initial gumbo_insert, not necessary */
        
    if (ctx->nflag & NGX_HTTP_DOM_TAG_SCRIPT && ctx->nSCRIPTOffset < ctx->nBODYOffset) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "[dom_encrypt] use script.");
        ctx->gumbo_insert = NGX_HTTP_DOM_TAG_SCRIPT;

    } else if (ctx->nflag & NGX_HTTP_DOM_TAG_META && ctx->nMETAOffset < ctx->nBODYOffset) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "[dom_encrypt] use meta.");
        ctx->gumbo_insert = NGX_HTTP_DOM_TAG_META;

    } else if (ctx->nflag & NGX_HTTP_DOM_TAG_HEAD && ctx->nHEADOffset < ctx->nBODYOffset) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "[dom_encrypt] use head.");
        ctx->gumbo_insert = NGX_HTTP_DOM_TAG_HEAD;

    } else if (ctx->nflag & NGX_HTTP_DOM_TAG_BODY) {
        
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "[dom_encrypt] use body.");
        ctx->gumbo_insert = NGX_HTTP_DOM_TAG_BODY;

    } else if (ctx->nflag & NGX_HTTP_DOM_TAG_HTML) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "[dom_encrypt] use html.");
        ctx->gumbo_insert = NGX_HTTP_DOM_TAG_HTML;

    } else if (ctx->nflag & NGX_HTTP_DOM_TAG_DOCUMENT) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "[dom_encrypt] use doc.");
        
        ctx->gumbo_insert = NGX_HTTP_DOM_TAG_DOCUMENT;
    }  else if (dlcf->force_mode == 1) {
        //we must insert the js. but we not check the suitable location to insert the js ..
        //so we insert the js directly to the first of html
        ctx->gumbo_insert = -1;
    }
    
    //we just insert the js at the start of the out..
    if (ctx->gumbo_insert == -1) {
        ngx_http_insert_js2(r, ctx);

        ctx->scan_end = body->data + body->len;
        
        denc_flush_scan_buf2(r, ctx);

        return NGX_OK;
    }

    output = gumbo_parse_with_options(&kGumboDefaultOptions, (const char *)body->data , body->len);
    if (output->root->v.element.tag == GUMBO_TAG_HTML) {
        value.data = body->data;
        value.len =  output->root->v.element.start_pos.offset;
        
        denc_out_chain_append_str2(r, ctx, &value);
        
        ctx->scan_begin = value.data + value.len;
    }

    //ngx_http_replace_node2(r, output->root, ctx, body);
    gumbo_destroy_output(&kGumboDefaultOptions, output);
    ctx->scan_end = body->data + body->len;
    denc_flush_scan_buf2(r, ctx);
    

    return NGX_OK;
}


/* insert js
 * */
ngx_int_t
ft_html_insert_js(ngx_http_request_t *r)
{
    transaction_t   *t;

    if (r != r->main) {
        return NGX_DECLINED;
    }
#if (NGX_DEBUG)
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "%M, fantax res_headr_handler, %V", ngx_current_msec, &r->uri);
#endif

    t = txn_from_req(r);
    if (t == NULL) {
        return NGX_DONE;
    }

    if (txn_is_passed(t, ACTION_PHASE_RESBODY)) {
        goto normal_out;
    }

    denc_loc_conf_t     *dlcf;
    denc_ctx_t          *ctx;
    ngx_str_t           *body = &t->res_body;

    ctx = txn_get_module_ctx(t, dom_encrypt_module);
    if (ctx == NULL) {
        //printf("denc_body_filter_action_cb ctx is null\n");
        denc_init_ctx(r);
    }

    if (r->ishtml == 0) {
        r->ishtml = ngx_check_html2(ctx, r, (const char *)body->data, body->len);
    }
    
    dlcf = txn_get_module_loc_conf(t, &dom_encrypt_module);

    if (!r->ishtml && !dlcf->force_mode) {
        goto normal_out;
    }
    
    if (dlcf->insert_js == 0) {
        goto normal_out;
    }
    
    if (ngx_is_white_url(r->uri, r, NGX_BUB_MODULE_JS_INSERT) == NGX_OK) {
        goto normal_out;
    }

    denc_out_chain_append_str2(r, ctx, body);
    
    if (ngx_http_replace_tag2(r, ctx, body) == NGX_OK) {
        return NGX_OK;
    }

    /*if we replace tag fails, we use the origin body...*/
    if (denc_out_chain_append_str2(r, ctx, body) != NGX_OK) {
        return NGX_ERROR;
    }

    t->res_body = ngx_chain2str(ctx->out, r->pool);
normal_out:

    /* Continue other ph->handlers process */ 

    if (r->connection->write->timedout) {
        r->connection->write->timedout = 0; 
    }

    if (r->connection->write->timer_set)
      ngx_event_del_timer(r->connection->write);

    return NGX_DECLINED;
}