#ifndef NGX_STREAM_TROJAN_RULES_H
#define NGX_STREAM_TROJAN_RULES_H

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_stream_trojan_protocol.h"


typedef enum {
    NGX_STREAM_TROJAN_RULE_DOMAIN_EXACT = 0,
    NGX_STREAM_TROJAN_RULE_DOMAIN_SUFFIX,
    NGX_STREAM_TROJAN_RULE_DOMAIN_WILDCARD,
    NGX_STREAM_TROJAN_RULE_DOMAIN_REGEX
} ngx_stream_trojan_rule_domain_type_e;


typedef struct {
    ngx_stream_trojan_rule_domain_type_e   type;
    ngx_str_t                              value;
#if (NGX_PCRE)
    ngx_regex_t                           *regex;
#endif
} ngx_stream_trojan_domain_rule_t;


typedef struct {
    ngx_cidr_t                             cidr;
} ngx_stream_trojan_ip_rule_t;


typedef struct {
    uint32_t                               seed;
} ngx_stream_trojan_mph_bucket_t;


typedef struct {
    uint32_t                               offset;
    uint16_t                               len;
    uint8_t                                flags;
} ngx_stream_trojan_mph_slot_t;


typedef struct {
    ngx_uint_t                             nelts;
    ngx_uint_t                             size;
    ngx_uint_t                             buckets_n;
    ngx_stream_trojan_mph_bucket_t        *buckets;
    ngx_stream_trojan_mph_slot_t          *slots;
    u_char                                *data;
} ngx_stream_trojan_domain_mph_t;


typedef struct {
    uint32_t                               addr;
} ngx_stream_trojan_ipv4_prefix_t;


typedef struct {
    ngx_uint_t                             nelts;
    ngx_stream_trojan_ipv4_prefix_t       *elts;
} ngx_stream_trojan_ipv4_prefix_bucket_t;


#if (NGX_HAVE_INET6)
typedef struct {
    u_char                                 addr[16];
} ngx_stream_trojan_ipv6_prefix_t;


typedef struct {
    ngx_uint_t                             nelts;
    ngx_stream_trojan_ipv6_prefix_t       *elts;
} ngx_stream_trojan_ipv6_prefix_bucket_t;
#endif


typedef struct {
    ngx_str_t                              tag;
    ngx_array_t                           domains;
    ngx_array_t                           ips;
    ngx_stream_trojan_domain_mph_t        exact;
    ngx_stream_trojan_domain_mph_t        suffix;
    ngx_array_t                          *regex_domains;
    ngx_stream_trojan_ipv4_prefix_bucket_t ipv4[33];
#if (NGX_HAVE_INET6)
    ngx_stream_trojan_ipv6_prefix_bucket_t ipv6[129];
#endif
    ngx_uint_t                            compiled;
} ngx_stream_trojan_route_rules_t;


typedef enum {
    NGX_STREAM_TROJAN_RULE_NO_MATCH = 0,
    NGX_STREAM_TROJAN_RULE_MATCH,
    NGX_STREAM_TROJAN_RULE_NOT_APPLICABLE
} ngx_stream_trojan_rule_match_e;


typedef struct {
    ngx_array_t                           *groups;
} ngx_stream_trojan_rules_conf_t;


typedef struct {
    ngx_stream_trojan_rules_conf_t         rules;
} ngx_stream_trojan_main_conf_t;


ngx_int_t ngx_stream_trojan_rule_domain_type(ngx_str_t *value,
    ngx_stream_trojan_rule_domain_type_e *type);
ngx_int_t ngx_stream_trojan_rule_reserved_value(ngx_str_t *value);
ngx_uint_t ngx_stream_trojan_rule_domain_match(
    ngx_stream_trojan_domain_rule_t *rule, ngx_str_t *host);
ngx_uint_t ngx_stream_trojan_rule_ip_match(ngx_stream_trojan_ip_rule_t *rule,
    struct sockaddr *sa);
ngx_stream_trojan_route_rules_t *ngx_stream_trojan_rules_find(
    ngx_stream_trojan_rules_conf_t *rules, ngx_str_t *tag);
ngx_stream_trojan_rule_match_e ngx_stream_trojan_route_rules_match_domain(
    ngx_stream_trojan_route_rules_t *group, ngx_str_t *host);
ngx_stream_trojan_rule_match_e ngx_stream_trojan_route_rules_match_ip(
    ngx_stream_trojan_route_rules_t *group, struct sockaddr *sa);
ngx_stream_trojan_rule_match_e ngx_stream_trojan_route_rules_match_target(
    ngx_stream_trojan_route_rules_t *group, ngx_stream_trojan_addr_t *target);
ngx_stream_trojan_rule_match_e ngx_stream_trojan_rules_match_domain(
    ngx_stream_trojan_rules_conf_t *rules, ngx_str_t *tag, ngx_str_t *host);
ngx_stream_trojan_rule_match_e ngx_stream_trojan_rules_match_ip(
    ngx_stream_trojan_rules_conf_t *rules, ngx_str_t *tag, struct sockaddr *sa);
ngx_int_t ngx_stream_trojan_rules_compile(ngx_conf_t *cf,
    ngx_stream_trojan_rules_conf_t *rules);

char *ngx_stream_trojan_route_rules_block(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
void *ngx_stream_trojan_create_main_conf(ngx_conf_t *cf);

#endif
