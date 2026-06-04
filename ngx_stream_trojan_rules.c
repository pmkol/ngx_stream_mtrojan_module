#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include <strings.h>

#include "ngx_stream_trojan_rules.h"


typedef struct {
    ngx_stream_trojan_route_rules_t  *group;
} ngx_stream_trojan_rules_block_ctx_t;


typedef struct {
    ngx_str_t                         key;
    uint8_t                           flags;
    uint32_t                          hash;
} ngx_stream_trojan_domain_build_entry_t;


typedef struct {
    ngx_uint_t                        bucket;
    ngx_uint_t                        count;
} ngx_stream_trojan_mph_bucket_sort_t;


#define NGX_STREAM_TROJAN_DOMAIN_SUFFIX_INCLUDE_ROOT  0x01


static char *ngx_stream_trojan_rules_block(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_stream_trojan_rules_tag_exists(ngx_array_t *groups,
    ngx_str_t *tag);
static char *ngx_stream_trojan_rules_add_domain(ngx_conf_t *cf,
    ngx_stream_trojan_route_rules_t *group, ngx_str_t *value);
static char *ngx_stream_trojan_rules_add_ip(ngx_conf_t *cf,
    ngx_stream_trojan_route_rules_t *group, ngx_str_t *value);
static ngx_stream_trojan_rules_conf_t *ngx_stream_trojan_rules_get_conf(
    ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_stream_trojan_route_rules_compile(ngx_conf_t *cf,
    ngx_stream_trojan_route_rules_t *group);
static ngx_int_t ngx_stream_trojan_route_rules_compile_domains(ngx_conf_t *cf,
    ngx_stream_trojan_route_rules_t *group);
static ngx_int_t ngx_stream_trojan_route_rules_compile_ips(ngx_conf_t *cf,
    ngx_stream_trojan_route_rules_t *group);
static ngx_int_t ngx_stream_trojan_route_rules_add_domain_entry(ngx_conf_t *cf,
    ngx_pool_t *pool, ngx_array_t *entries, u_char *data, size_t len,
    uint8_t flags);
static ngx_int_t ngx_stream_trojan_route_rules_build_domain_mph(ngx_conf_t *cf,
    ngx_pool_t *temp_pool, ngx_array_t *entries,
    ngx_stream_trojan_domain_mph_t *mph);
static ngx_stream_trojan_mph_slot_t *
    ngx_stream_trojan_route_rules_domain_mph_find(
    ngx_stream_trojan_domain_mph_t *mph, u_char *data, size_t len);
static uint32_t ngx_stream_trojan_route_rules_hash(u_char *data, size_t len,
    uint32_t seed);
static ngx_uint_t ngx_stream_trojan_route_rules_next_power(ngx_uint_t n);
static ngx_uint_t ngx_stream_trojan_route_rules_ipv4_prefix(uint32_t mask);
static uint32_t ngx_stream_trojan_route_rules_ipv4_mask(ngx_uint_t prefix);
#if (NGX_HAVE_INET6)
static ngx_uint_t ngx_stream_trojan_route_rules_ipv6_prefix(u_char *mask);
static void ngx_stream_trojan_route_rules_ipv6_mask(u_char *dst, u_char *src,
    ngx_uint_t prefix);
#endif
static int ngx_libc_cdecl ngx_stream_trojan_cmp_domain_entries(
    const void *one, const void *two);
static int ngx_libc_cdecl ngx_stream_trojan_cmp_mph_buckets(
    const void *one, const void *two);
static int ngx_libc_cdecl ngx_stream_trojan_cmp_ipv4_prefix(
    const void *one, const void *two);
#if (NGX_HAVE_INET6)
static int ngx_libc_cdecl ngx_stream_trojan_cmp_ipv6_prefix(
    const void *one, const void *two);
#endif
static ngx_uint_t ngx_stream_trojan_route_rules_ipv4_find(
    ngx_stream_trojan_ipv4_prefix_bucket_t *bucket, uint32_t addr);
#if (NGX_HAVE_INET6)
static ngx_uint_t ngx_stream_trojan_route_rules_ipv6_find(
    ngx_stream_trojan_ipv6_prefix_bucket_t *bucket, u_char *addr);
#endif
static ngx_int_t ngx_stream_trojan_route_rules_target_to_sockaddr(
    ngx_stream_trojan_addr_t *target, ngx_sockaddr_t *sockaddr);


void *
ngx_stream_trojan_create_main_conf(ngx_conf_t *cf)
{
    ngx_stream_trojan_main_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_trojan_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


ngx_int_t
ngx_stream_trojan_rule_reserved_value(ngx_str_t *value)
{
    if (value->len == sizeof("include") - 1
        && ngx_strncmp(value->data, "include", value->len) == 0)
    {
        return 1;
    }

    return 0;
}


ngx_int_t
ngx_stream_trojan_rule_domain_type(ngx_str_t *value,
    ngx_stream_trojan_rule_domain_type_e *type)
{
    if (value->len == 0) {
        return NGX_ERROR;
    }

    if (ngx_stream_trojan_rule_reserved_value(value)) {
        return NGX_ERROR;
    }

    if (value->data[0] == '~') {
        if (value->len == 1) {
            return NGX_ERROR;
        }

        *type = NGX_STREAM_TROJAN_RULE_DOMAIN_REGEX;
        return NGX_OK;
    }

    if (value->data[0] == '.') {
        if (value->len == 1) {
            return NGX_ERROR;
        }

        *type = NGX_STREAM_TROJAN_RULE_DOMAIN_SUFFIX;
        return NGX_OK;
    }

    if (value->len > 2
        && value->data[0] == '*'
        && value->data[1] == '.')
    {
        *type = NGX_STREAM_TROJAN_RULE_DOMAIN_WILDCARD;
        return NGX_OK;
    }

    *type = NGX_STREAM_TROJAN_RULE_DOMAIN_EXACT;
    return NGX_OK;
}


ngx_uint_t
ngx_stream_trojan_rule_domain_match(ngx_stream_trojan_domain_rule_t *rule,
    ngx_str_t *host)
{
    ngx_str_t  suffix;

    if (rule == NULL || host == NULL || host->len == 0) {
        return 0;
    }

    switch (rule->type) {

    case NGX_STREAM_TROJAN_RULE_DOMAIN_EXACT:
        return host->len == rule->value.len
               && strncasecmp((char *) host->data, (char *) rule->value.data,
                              host->len)
                  == 0;

    case NGX_STREAM_TROJAN_RULE_DOMAIN_SUFFIX:
        suffix.data = rule->value.data + 1;
        suffix.len = rule->value.len - 1;

        if (host->len == suffix.len) {
            return strncasecmp((char *) host->data, (char *) suffix.data,
                               host->len)
                   == 0;
        }

        if (host->len <= suffix.len + 1) {
            return 0;
        }

        if (host->data[host->len - suffix.len - 1] != '.') {
            return 0;
        }

        return strncasecmp((char *) (host->data + host->len - suffix.len),
                           (char *) suffix.data, suffix.len)
               == 0;

    case NGX_STREAM_TROJAN_RULE_DOMAIN_WILDCARD:
        suffix.data = rule->value.data + 2;
        suffix.len = rule->value.len - 2;

        if (host->len <= suffix.len + 1) {
            return 0;
        }

        if (host->data[host->len - suffix.len - 1] != '.') {
            return 0;
        }

        return strncasecmp((char *) (host->data + host->len - suffix.len),
                           (char *) suffix.data, suffix.len)
               == 0;

    case NGX_STREAM_TROJAN_RULE_DOMAIN_REGEX:
#if (NGX_PCRE)
        return ngx_regex_exec(rule->regex, host, NULL, 0) >= 0;
#else
        return 0;
#endif
    }

    return 0;
}


ngx_uint_t
ngx_stream_trojan_rule_ip_match(ngx_stream_trojan_ip_rule_t *rule,
    struct sockaddr *sa)
{
    ngx_uint_t              n;
    struct sockaddr_in     *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6    *sin6;
#endif

    if (rule == NULL || sa == NULL || sa->sa_family != rule->cidr.family) {
        return 0;
    }

    if (sa->sa_family == AF_INET) {
        sin = (struct sockaddr_in *) sa;
        return (sin->sin_addr.s_addr & rule->cidr.u.in.mask)
               == rule->cidr.u.in.addr;
    }

#if (NGX_HAVE_INET6)
    if (sa->sa_family == AF_INET6) {
        sin6 = (struct sockaddr_in6 *) sa;

        for (n = 0; n < 16; n++) {
            if ((sin6->sin6_addr.s6_addr[n] & rule->cidr.u.in6.mask.s6_addr[n])
                != rule->cidr.u.in6.addr.s6_addr[n])
            {
                return 0;
            }
        }

        return 1;
    }
#endif

    return 0;
}


ngx_stream_trojan_route_rules_t *
ngx_stream_trojan_rules_find(ngx_stream_trojan_rules_conf_t *rules,
    ngx_str_t *tag)
{
    ngx_uint_t                         i;
    ngx_stream_trojan_route_rules_t   *group;

    if (rules == NULL || rules->groups == NULL) {
        return NULL;
    }

    group = rules->groups->elts;

    for (i = 0; i < rules->groups->nelts; i++) {
        if (group[i].tag.len == tag->len
            && ngx_strncmp(group[i].tag.data, tag->data, tag->len) == 0)
        {
            return &group[i];
        }
    }

    return NULL;
}


ngx_stream_trojan_rule_match_e
ngx_stream_trojan_route_rules_match_domain(
    ngx_stream_trojan_route_rules_t *group, ngx_str_t *host)
{
    ngx_uint_t                         i, suffix;
    ngx_stream_trojan_domain_rule_t   *rule;
    ngx_stream_trojan_mph_slot_t      *slot;
    u_char                             name[255];

    if (group == NULL || group->domains.nelts == 0) {
        return NGX_STREAM_TROJAN_RULE_NOT_APPLICABLE;
    }

    if (group->compiled && host->len <= sizeof(name)) {
        for (i = 0; i < host->len; i++) {
            name[i] = ngx_tolower(host->data[i]);
        }

        if (ngx_stream_trojan_route_rules_domain_mph_find(&group->exact, name,
                                                          host->len)
            != NULL)
        {
            return NGX_STREAM_TROJAN_RULE_MATCH;
        }

        slot = ngx_stream_trojan_route_rules_domain_mph_find(&group->suffix,
                                                             name, host->len);
        if (slot != NULL
            && (slot->flags
                & NGX_STREAM_TROJAN_DOMAIN_SUFFIX_INCLUDE_ROOT))
        {
            return NGX_STREAM_TROJAN_RULE_MATCH;
        }

        for (suffix = 0; suffix < host->len; suffix++) {
            if (name[suffix] != '.') {
                continue;
            }

            slot = ngx_stream_trojan_route_rules_domain_mph_find(
                &group->suffix, name + suffix + 1, host->len - suffix - 1);
            if (slot != NULL) {
                return NGX_STREAM_TROJAN_RULE_MATCH;
            }
        }

        if (group->regex_domains == NULL || group->regex_domains->nelts == 0) {
            return NGX_STREAM_TROJAN_RULE_NO_MATCH;
        }

        rule = group->regex_domains->elts;

        for (i = 0; i < group->regex_domains->nelts; i++) {
            if (ngx_stream_trojan_rule_domain_match(&rule[i], host)) {
                return NGX_STREAM_TROJAN_RULE_MATCH;
            }
        }

        return NGX_STREAM_TROJAN_RULE_NO_MATCH;
    }

    rule = group->domains.elts;
    for (i = 0; i < group->domains.nelts; i++) {
        if (ngx_stream_trojan_rule_domain_match(&rule[i], host)) {
            return NGX_STREAM_TROJAN_RULE_MATCH;
        }
    }

    return NGX_STREAM_TROJAN_RULE_NO_MATCH;
}


ngx_stream_trojan_rule_match_e
ngx_stream_trojan_route_rules_match_ip(ngx_stream_trojan_route_rules_t *group,
    struct sockaddr *sa)
{
    ngx_int_t                     prefix;
    ngx_uint_t                    i;
    ngx_stream_trojan_ip_rule_t  *rule;
    struct sockaddr_in           *sin;
    uint32_t                      addr, masked;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6          *sin6;
    u_char                        masked6[16];
#endif

    if (group == NULL || group->ips.nelts == 0) {
        return NGX_STREAM_TROJAN_RULE_NOT_APPLICABLE;
    }

    if (group->compiled) {
        if (sa->sa_family == AF_INET) {
            sin = (struct sockaddr_in *) sa;
            addr = ntohl(sin->sin_addr.s_addr);

            for (prefix = 32; prefix >= 0; prefix--) {
                if (group->ipv4[prefix].nelts == 0) {
                    continue;
                }

                masked = addr
                         & ngx_stream_trojan_route_rules_ipv4_mask(prefix);

                if (ngx_stream_trojan_route_rules_ipv4_find(
                    &group->ipv4[prefix], masked))
                {
                    return NGX_STREAM_TROJAN_RULE_MATCH;
                }
            }

            return NGX_STREAM_TROJAN_RULE_NO_MATCH;
        }

#if (NGX_HAVE_INET6)
        if (sa->sa_family == AF_INET6) {
            sin6 = (struct sockaddr_in6 *) sa;

            for (prefix = 128; prefix >= 0; prefix--) {
                if (group->ipv6[prefix].nelts == 0) {
                    continue;
                }

                ngx_stream_trojan_route_rules_ipv6_mask(
                    masked6, sin6->sin6_addr.s6_addr, prefix);

                if (ngx_stream_trojan_route_rules_ipv6_find(
                    &group->ipv6[prefix], masked6))
                {
                    return NGX_STREAM_TROJAN_RULE_MATCH;
                }
            }

            return NGX_STREAM_TROJAN_RULE_NO_MATCH;
        }
#endif

        return NGX_STREAM_TROJAN_RULE_NO_MATCH;
    }

    rule = group->ips.elts;

    for (i = 0; i < group->ips.nelts; i++) {
        if (ngx_stream_trojan_rule_ip_match(&rule[i], sa)) {
            return NGX_STREAM_TROJAN_RULE_MATCH;
        }
    }

    return NGX_STREAM_TROJAN_RULE_NO_MATCH;
}


ngx_stream_trojan_rule_match_e
ngx_stream_trojan_rules_match_domain(ngx_stream_trojan_rules_conf_t *rules,
    ngx_str_t *tag, ngx_str_t *host)
{
    return ngx_stream_trojan_route_rules_match_domain(
        ngx_stream_trojan_rules_find(rules, tag), host);
}


ngx_stream_trojan_rule_match_e
ngx_stream_trojan_rules_match_ip(ngx_stream_trojan_rules_conf_t *rules,
    ngx_str_t *tag, struct sockaddr *sa)
{
    return ngx_stream_trojan_route_rules_match_ip(
        ngx_stream_trojan_rules_find(rules, tag), sa);
}


ngx_stream_trojan_rule_match_e
ngx_stream_trojan_route_rules_match_target(
    ngx_stream_trojan_route_rules_t *group, ngx_stream_trojan_addr_t *target)
{
    ngx_str_t                       host;
    ngx_sockaddr_t                  sockaddr;

    if (target == NULL) {
        return NGX_STREAM_TROJAN_RULE_NOT_APPLICABLE;
    }

    if (target->type == NGX_STREAM_TROJAN_ADDR_DOMAIN) {
        host.data = target->host;
        host.len = target->host_len;

        if (group == NULL || group->domains.nelts == 0) {
            return NGX_STREAM_TROJAN_RULE_NO_MATCH;
        }

        return ngx_stream_trojan_route_rules_match_domain(group, &host);
    }

    if (ngx_stream_trojan_route_rules_target_to_sockaddr(target, &sockaddr)
        == NGX_OK)
    {
        return ngx_stream_trojan_route_rules_match_ip(group,
                                                      &sockaddr.sockaddr);
    }

    return NGX_STREAM_TROJAN_RULE_NOT_APPLICABLE;
}


ngx_int_t
ngx_stream_trojan_rules_compile(ngx_conf_t *cf,
    ngx_stream_trojan_rules_conf_t *rules)
{
    ngx_uint_t                       i;
    ngx_stream_trojan_route_rules_t *group;

    if (rules == NULL || rules->groups == NULL) {
        return NGX_OK;
    }

    group = rules->groups->elts;

    for (i = 0; i < rules->groups->nelts; i++) {
        if (ngx_stream_trojan_route_rules_compile(cf, &group[i]) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


char *
ngx_stream_trojan_route_rules_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_trojan_rules_conf_t       *rules;
    ngx_stream_trojan_route_rules_t      *group;
    ngx_stream_trojan_rules_block_ctx_t   block;
    ngx_str_t                            *value;
    ngx_conf_t                            save;
    char                                 *rv;

    value = cf->args->elts;
    rules = ngx_stream_trojan_rules_get_conf(cf, cmd, conf);
    if (rules == NULL) {
        return NGX_CONF_ERROR;
    }

    if (rules->groups == NULL) {
        rules->groups = ngx_array_create(
            cf->pool, 2, sizeof(ngx_stream_trojan_route_rules_t));
        if (rules->groups == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    if (ngx_stream_trojan_rules_tag_exists(rules->groups, &value[1])) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate route_rules tag \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    group = ngx_array_push(rules->groups);
    if (group == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(group, sizeof(*group));
    group->tag = value[1];

    if (ngx_array_init(&group->domains, cf->pool, 4,
                       sizeof(ngx_stream_trojan_domain_rule_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_array_init(&group->ips, cf->pool, 4,
                       sizeof(ngx_stream_trojan_ip_rule_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    block.group = group;

    save = *cf;
    cf->handler = ngx_stream_trojan_rules_block;
    cf->handler_conf = &block;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    (void) cmd;
    return rv;
}


static ngx_int_t
ngx_stream_trojan_rules_tag_exists(ngx_array_t *groups, ngx_str_t *tag)
{
    ngx_uint_t                         i;
    ngx_stream_trojan_route_rules_t   *group;

    group = groups->elts;

    for (i = 0; i < groups->nelts; i++) {
        if (group[i].tag.len == tag->len
            && ngx_strncmp(group[i].tag.data, tag->data, tag->len) == 0)
        {
            return 1;
        }
    }

    return 0;
}


static ngx_stream_trojan_rules_conf_t *
ngx_stream_trojan_rules_get_conf(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_trojan_main_conf_t  *tmcf;

    if (cf->cmd_type == NGX_STREAM_MAIN_CONF) {
        tmcf = conf;
        return &tmcf->rules;
    }

    if (cf->cmd_type == NGX_STREAM_SRV_CONF) {
        return (ngx_stream_trojan_rules_conf_t *)
               ((u_char *) conf + cmd->offset);
    }

    return NULL;
}


static char *
ngx_stream_trojan_rules_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_trojan_rules_block_ctx_t  *block = conf;
    ngx_str_t                            *value;
    ngx_uint_t                            i;
    char                                 *rv;

    value = cf->args->elts;

    if (ngx_strcmp(value[0].data, "include") == 0) {
        if (cf->args->nelts != 2) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "include in rules block requires one file");
            return NGX_CONF_ERROR;
        }

        return ngx_conf_include(cf, cmd, conf);
    }

    if (ngx_strcmp(value[0].data, "domain") == 0) {
        if (cf->args->nelts < 2) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "domain requires at least one value");
            return NGX_CONF_ERROR;
        }

        for (i = 1; i < cf->args->nelts; i++) {
            rv = ngx_stream_trojan_rules_add_domain(cf, block->group,
                                                    &value[i]);
            if (rv != NGX_CONF_OK) {
                return rv;
            }
        }

        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[0].data, "ip") == 0) {
        if (cf->args->nelts < 2) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "ip requires at least one value");
            return NGX_CONF_ERROR;
        }

        for (i = 1; i < cf->args->nelts; i++) {
            rv = ngx_stream_trojan_rules_add_ip(cf, block->group, &value[i]);
            if (rv != NGX_CONF_OK) {
                return rv;
            }
        }

        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "unknown directive \"%V\" in rules block", &value[0]);

    (void) cmd;
    return NGX_CONF_ERROR;
}


static char *
ngx_stream_trojan_rules_add_domain(ngx_conf_t *cf,
    ngx_stream_trojan_route_rules_t *group, ngx_str_t *value)
{
    ngx_stream_trojan_domain_rule_t       *rule;
    ngx_stream_trojan_rule_domain_type_e   type;
#if (NGX_PCRE)
    ngx_regex_compile_t                    rc;
    u_char                                 errstr[NGX_MAX_CONF_ERRSTR];
    ngx_str_t                              pattern;
#endif

    if (ngx_stream_trojan_rule_reserved_value(value)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"include\" is not allowed inside domain values; "
                           "missing \";\" before include?");
        return NGX_CONF_ERROR;
    }

    if (ngx_stream_trojan_rule_domain_type(value, &type) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid domain rule \"%V\"", value);
        return NGX_CONF_ERROR;
    }

    rule = ngx_array_push(&group->domains);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(rule, sizeof(*rule));
    rule->type = type;
    rule->value = *value;

    if (type == NGX_STREAM_TROJAN_RULE_DOMAIN_REGEX) {
#if (NGX_PCRE)
        pattern.data = value->data + 1;
        pattern.len = value->len - 1;

        ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
        rc.pattern = pattern;
        rc.pool = cf->pool;
        rc.err.len = NGX_MAX_CONF_ERRSTR;
        rc.err.data = errstr;

        if (ngx_regex_compile(&rc) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid domain regex \"%V\": %V",
                               value, &rc.err);
            return NGX_CONF_ERROR;
        }

        rule->regex = rc.regex;
#else
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "domain regex \"%V\" requires PCRE support",
                           value);
        return NGX_CONF_ERROR;
#endif
    }

    return NGX_CONF_OK;
}


static char *
ngx_stream_trojan_rules_add_ip(ngx_conf_t *cf,
    ngx_stream_trojan_route_rules_t *group, ngx_str_t *value)
{
    ngx_stream_trojan_ip_rule_t  *rule;

    if (ngx_stream_trojan_rule_reserved_value(value)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"include\" is not allowed inside ip values; "
                           "missing \";\" before include?");
        return NGX_CONF_ERROR;
    }

    rule = ngx_array_push(&group->ips);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(rule, sizeof(*rule));

    if (ngx_ptocidr(value, &rule->cidr) == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid ip rule \"%V\"", value);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_stream_trojan_route_rules_compile(ngx_conf_t *cf,
    ngx_stream_trojan_route_rules_t *group)
{
    if (group->compiled) {
        return NGX_OK;
    }

    if (ngx_stream_trojan_route_rules_compile_domains(cf, group) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_stream_trojan_route_rules_compile_ips(cf, group) != NGX_OK) {
        return NGX_ERROR;
    }

    group->compiled = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_route_rules_compile_domains(ngx_conf_t *cf,
    ngx_stream_trojan_route_rules_t *group)
{
    ngx_uint_t                        i;
    ngx_pool_t                       *temp_pool;
    ngx_array_t                      *exact, *suffix;
    ngx_stream_trojan_domain_rule_t  *rule, *regex_rule;

    if (group->domains.nelts == 0) {
        return NGX_OK;
    }

    temp_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, cf->log);
    if (temp_pool == NULL) {
        return NGX_ERROR;
    }

    exact = ngx_array_create(temp_pool, group->domains.nelts,
                             sizeof(ngx_stream_trojan_domain_build_entry_t));
    if (exact == NULL) {
        ngx_destroy_pool(temp_pool);
        return NGX_ERROR;
    }

    suffix = ngx_array_create(temp_pool, group->domains.nelts,
                              sizeof(ngx_stream_trojan_domain_build_entry_t));
    if (suffix == NULL) {
        ngx_destroy_pool(temp_pool);
        return NGX_ERROR;
    }

    rule = group->domains.elts;

    for (i = 0; i < group->domains.nelts; i++) {
        switch (rule[i].type) {

        case NGX_STREAM_TROJAN_RULE_DOMAIN_EXACT:
            if (ngx_stream_trojan_route_rules_add_domain_entry(
                cf, temp_pool, exact, rule[i].value.data, rule[i].value.len, 0)
                != NGX_OK)
            {
                ngx_destroy_pool(temp_pool);
                return NGX_ERROR;
            }

            break;

        case NGX_STREAM_TROJAN_RULE_DOMAIN_SUFFIX:
            if (ngx_stream_trojan_route_rules_add_domain_entry(
                cf, temp_pool, suffix, rule[i].value.data + 1,
                rule[i].value.len - 1,
                NGX_STREAM_TROJAN_DOMAIN_SUFFIX_INCLUDE_ROOT)
                != NGX_OK)
            {
                ngx_destroy_pool(temp_pool);
                return NGX_ERROR;
            }

            break;

        case NGX_STREAM_TROJAN_RULE_DOMAIN_WILDCARD:
            if (ngx_stream_trojan_route_rules_add_domain_entry(
                cf, temp_pool, suffix, rule[i].value.data + 2,
                rule[i].value.len - 2, 0)
                != NGX_OK)
            {
                ngx_destroy_pool(temp_pool);
                return NGX_ERROR;
            }

            break;

        case NGX_STREAM_TROJAN_RULE_DOMAIN_REGEX:
            if (group->regex_domains == NULL) {
                group->regex_domains = ngx_array_create(
                    cf->pool, 2, sizeof(ngx_stream_trojan_domain_rule_t));
                if (group->regex_domains == NULL) {
                    ngx_destroy_pool(temp_pool);
                    return NGX_ERROR;
                }
            }

            regex_rule = ngx_array_push(group->regex_domains);
            if (regex_rule == NULL) {
                ngx_destroy_pool(temp_pool);
                return NGX_ERROR;
            }

            *regex_rule = rule[i];
            break;
        }
    }

    if (ngx_stream_trojan_route_rules_build_domain_mph(cf, temp_pool, exact,
                                                       &group->exact)
        != NGX_OK)
    {
        ngx_destroy_pool(temp_pool);
        return NGX_ERROR;
    }

    if (ngx_stream_trojan_route_rules_build_domain_mph(cf, temp_pool, suffix,
                                                       &group->suffix)
        != NGX_OK)
    {
        ngx_destroy_pool(temp_pool);
        return NGX_ERROR;
    }

    ngx_destroy_pool(temp_pool);

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_route_rules_compile_ips(ngx_conf_t *cf,
    ngx_stream_trojan_route_rules_t *group)
{
    ngx_uint_t                              i, n, prefix;
    ngx_uint_t                              counts4[33], cursors4[33];
    ngx_stream_trojan_ip_rule_t           *rule;
    uint32_t                                mask, addr;
#if (NGX_HAVE_INET6)
    ngx_uint_t                              counts6[129], cursors6[129];
#endif

    if (group->ips.nelts == 0) {
        return NGX_OK;
    }

    ngx_memzero(counts4, sizeof(counts4));
    ngx_memzero(cursors4, sizeof(cursors4));

#if (NGX_HAVE_INET6)
    ngx_memzero(counts6, sizeof(counts6));
    ngx_memzero(cursors6, sizeof(cursors6));
#endif

    rule = group->ips.elts;

    for (i = 0; i < group->ips.nelts; i++) {
        if (rule[i].cidr.family == AF_INET) {
            prefix = ngx_stream_trojan_route_rules_ipv4_prefix(
                ntohl(rule[i].cidr.u.in.mask));
            counts4[prefix]++;

#if (NGX_HAVE_INET6)
        } else if (rule[i].cidr.family == AF_INET6) {
            prefix = ngx_stream_trojan_route_rules_ipv6_prefix(
                rule[i].cidr.u.in6.mask.s6_addr);
            counts6[prefix]++;
#endif
        }
    }

    for (i = 0; i <= 32; i++) {
        if (counts4[i] == 0) {
            continue;
        }

        group->ipv4[i].elts = ngx_pnalloc(
            cf->pool, counts4[i] * sizeof(ngx_stream_trojan_ipv4_prefix_t));
        if (group->ipv4[i].elts == NULL) {
            return NGX_ERROR;
        }

        group->ipv4[i].nelts = counts4[i];
    }

#if (NGX_HAVE_INET6)
    for (i = 0; i <= 128; i++) {
        if (counts6[i] == 0) {
            continue;
        }

        group->ipv6[i].elts = ngx_pnalloc(
            cf->pool, counts6[i] * sizeof(ngx_stream_trojan_ipv6_prefix_t));
        if (group->ipv6[i].elts == NULL) {
            return NGX_ERROR;
        }

        group->ipv6[i].nelts = counts6[i];
    }
#endif

    for (i = 0; i < group->ips.nelts; i++) {
        if (rule[i].cidr.family == AF_INET) {
            prefix = ngx_stream_trojan_route_rules_ipv4_prefix(
                ntohl(rule[i].cidr.u.in.mask));
            mask = ngx_stream_trojan_route_rules_ipv4_mask(prefix);
            addr = ntohl(rule[i].cidr.u.in.addr) & mask;
            group->ipv4[prefix].elts[cursors4[prefix]++].addr = addr;

#if (NGX_HAVE_INET6)
        } else if (rule[i].cidr.family == AF_INET6) {
            prefix = ngx_stream_trojan_route_rules_ipv6_prefix(
                rule[i].cidr.u.in6.mask.s6_addr);
            ngx_stream_trojan_route_rules_ipv6_mask(
                group->ipv6[prefix].elts[cursors6[prefix]++].addr,
                rule[i].cidr.u.in6.addr.s6_addr, prefix);
#endif
        }
    }

    for (i = 0; i <= 32; i++) {
        if (group->ipv4[i].nelts == 0) {
            continue;
        }

        ngx_qsort(group->ipv4[i].elts, (size_t) group->ipv4[i].nelts,
                  sizeof(ngx_stream_trojan_ipv4_prefix_t),
                  ngx_stream_trojan_cmp_ipv4_prefix);

        n = 0;
        for (prefix = 0; prefix < group->ipv4[i].nelts; prefix++) {
            if (n == 0
                || group->ipv4[i].elts[n - 1].addr
                   != group->ipv4[i].elts[prefix].addr)
            {
                group->ipv4[i].elts[n++] = group->ipv4[i].elts[prefix];
            }
        }

        group->ipv4[i].nelts = n;
    }

#if (NGX_HAVE_INET6)
    for (i = 0; i <= 128; i++) {
        if (group->ipv6[i].nelts == 0) {
            continue;
        }

        ngx_qsort(group->ipv6[i].elts, (size_t) group->ipv6[i].nelts,
                  sizeof(ngx_stream_trojan_ipv6_prefix_t),
                  ngx_stream_trojan_cmp_ipv6_prefix);

        n = 0;
        for (prefix = 0; prefix < group->ipv6[i].nelts; prefix++) {
            if (n == 0
                || ngx_memcmp(group->ipv6[i].elts[n - 1].addr,
                              group->ipv6[i].elts[prefix].addr, 16)
                   != 0)
            {
                group->ipv6[i].elts[n++] = group->ipv6[i].elts[prefix];
            }
        }

        group->ipv6[i].nelts = n;
    }
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_route_rules_add_domain_entry(ngx_conf_t *cf,
    ngx_pool_t *pool, ngx_array_t *entries, u_char *data, size_t len,
    uint8_t flags)
{
    size_t                                      i;
    ngx_stream_trojan_domain_build_entry_t    *entry;

    if (len == 0 || len > 255) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid domain rule length");
        return NGX_ERROR;
    }

    entry = ngx_array_push(entries);
    if (entry == NULL) {
        return NGX_ERROR;
    }

    entry->key.data = ngx_pnalloc(pool, len);
    if (entry->key.data == NULL) {
        return NGX_ERROR;
    }

    entry->key.len = len;
    entry->flags = flags;

    for (i = 0; i < len; i++) {
        entry->key.data[i] = ngx_tolower(data[i]);
    }

    entry->hash = ngx_stream_trojan_route_rules_hash(entry->key.data, len, 0);

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_route_rules_build_domain_mph(ngx_conf_t *cf,
    ngx_pool_t *temp_pool, ngx_array_t *entries,
    ngx_stream_trojan_domain_mph_t *mph)
{
    ngx_uint_t                                  i, n, size, limit, bucket;
    ngx_uint_t                                  buckets_n, b, seed, pos, j;
    ngx_uint_t                                  offset, count, data_size;
    ngx_uint_t                                 *bucket_counts, *bucket_offsets;
    ngx_uint_t                                 *bucket_fill, *bucket_items;
    ngx_uint_t                                 *used, *positions, *probe;
    ngx_uint_t                                  ok, duplicate;
    ngx_stream_trojan_mph_bucket_sort_t       *sorted;
    ngx_stream_trojan_domain_build_entry_t    *entry, *unique, *e;
    ngx_stream_trojan_mph_bucket_t            *buckets;
    ngx_stream_trojan_mph_slot_t              *slot;

    if (entries->nelts == 0) {
        return NGX_OK;
    }

    entry = entries->elts;
    ngx_qsort(entry, (size_t) entries->nelts,
              sizeof(ngx_stream_trojan_domain_build_entry_t),
              ngx_stream_trojan_cmp_domain_entries);

    unique = entry;
    n = 0;

    for (i = 0; i < entries->nelts; i++) {
        if (n != 0
            && unique[n - 1].key.len == entry[i].key.len
            && ngx_memcmp(unique[n - 1].key.data, entry[i].key.data,
                         entry[i].key.len)
               == 0)
        {
            unique[n - 1].flags |= entry[i].flags;
            continue;
        }

        unique[n++] = entry[i];
    }

    if (n == 0) {
        return NGX_OK;
    }

    buckets_n = ngx_stream_trojan_route_rules_next_power(n / 4 + 1);

    bucket_counts = ngx_pcalloc(temp_pool, buckets_n * sizeof(ngx_uint_t));
    bucket_offsets = ngx_pcalloc(temp_pool, buckets_n * sizeof(ngx_uint_t));
    bucket_fill = ngx_pcalloc(temp_pool, buckets_n * sizeof(ngx_uint_t));
    sorted = ngx_pnalloc(temp_pool,
                         buckets_n
                         * sizeof(ngx_stream_trojan_mph_bucket_sort_t));
    bucket_items = ngx_pnalloc(temp_pool, n * sizeof(ngx_uint_t));
    positions = ngx_pnalloc(temp_pool, n * sizeof(ngx_uint_t));
    probe = ngx_pnalloc(temp_pool, n * sizeof(ngx_uint_t));

    if (bucket_counts == NULL || bucket_offsets == NULL
        || bucket_fill == NULL || sorted == NULL || bucket_items == NULL
        || positions == NULL || probe == NULL)
    {
        return NGX_ERROR;
    }

    for (i = 0; i < n; i++) {
        bucket_counts[unique[i].hash & (buckets_n - 1)]++;
    }

    offset = 0;
    for (i = 0; i < buckets_n; i++) {
        bucket_offsets[i] = offset;
        sorted[i].bucket = i;
        sorted[i].count = bucket_counts[i];
        offset += bucket_counts[i];
    }

    for (i = 0; i < n; i++) {
        bucket = unique[i].hash & (buckets_n - 1);
        bucket_items[bucket_offsets[bucket] + bucket_fill[bucket]++] = i;
    }

    ngx_qsort(sorted, (size_t) buckets_n,
              sizeof(ngx_stream_trojan_mph_bucket_sort_t),
              ngx_stream_trojan_cmp_mph_buckets);

    limit = n * 2 + 1;

    for (size = n; size <= limit; size += n / 8 + 1) {
        used = ngx_pcalloc(temp_pool, size * sizeof(ngx_uint_t));
        buckets = ngx_pcalloc(temp_pool,
                              buckets_n
                              * sizeof(ngx_stream_trojan_mph_bucket_t));

        if (used == NULL || buckets == NULL) {
            return NGX_ERROR;
        }

        for (b = 0; b < buckets_n; b++) {
            bucket = sorted[b].bucket;
            count = sorted[b].count;

            if (count == 0) {
                continue;
            }

            for (seed = 1; seed < 65536; seed++) {
                ok = 1;

                for (i = 0; i < count; i++) {
                    e = &unique[bucket_items[bucket_offsets[bucket] + i]];
                    pos = ngx_stream_trojan_route_rules_hash(
                              e->key.data, e->key.len, seed)
                          % size;

                    if (used[pos]) {
                        ok = 0;
                        break;
                    }

                    duplicate = 0;
                    for (j = 0; j < i; j++) {
                        if (probe[j] == pos) {
                            duplicate = 1;
                            break;
                        }
                    }

                    if (duplicate) {
                        ok = 0;
                        break;
                    }

                    probe[i] = pos;
                }

                if (ok) {
                    break;
                }
            }

            if (seed == 65536) {
                break;
            }

            buckets[bucket].seed = (uint32_t) seed;

            for (i = 0; i < count; i++) {
                e = &unique[bucket_items[bucket_offsets[bucket] + i]];
                pos = ngx_stream_trojan_route_rules_hash(
                          e->key.data, e->key.len, seed)
                      % size;
                used[pos] = 1;
                positions[bucket_items[bucket_offsets[bucket] + i]] = pos;
            }
        }

        if (b != buckets_n) {
            continue;
        }

        mph->slots = ngx_pcalloc(cf->pool,
                                 size
                                 * sizeof(ngx_stream_trojan_mph_slot_t));
        mph->buckets = ngx_pnalloc(cf->pool,
                                   buckets_n
                                   * sizeof(ngx_stream_trojan_mph_bucket_t));
        if (mph->slots == NULL || mph->buckets == NULL) {
            return NGX_ERROR;
        }

        data_size = 0;
        for (i = 0; i < n; i++) {
            data_size += unique[i].key.len;
        }

        mph->data = ngx_pnalloc(cf->pool, data_size);
        if (mph->data == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(mph->buckets, buckets,
                   buckets_n * sizeof(ngx_stream_trojan_mph_bucket_t));

        offset = 0;
        for (i = 0; i < n; i++) {
            slot = &mph->slots[positions[i]];
            slot->offset = offset;
            slot->len = (uint16_t) unique[i].key.len;
            slot->flags = unique[i].flags;

            ngx_memcpy(mph->data + offset, unique[i].key.data,
                       unique[i].key.len);
            offset += unique[i].key.len;
        }

        mph->nelts = n;
        mph->size = size;
        mph->buckets_n = buckets_n;

        return NGX_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "could not build compact route_rules domain matcher");

    return NGX_ERROR;
}


static ngx_stream_trojan_mph_slot_t *
ngx_stream_trojan_route_rules_domain_mph_find(
    ngx_stream_trojan_domain_mph_t *mph, u_char *data, size_t len)
{
    uint32_t                          hash;
    ngx_uint_t                        bucket, pos;
    ngx_stream_trojan_mph_slot_t     *slot;

    if (mph == NULL || mph->size == 0 || len == 0 || len > 255) {
        return NULL;
    }

    hash = ngx_stream_trojan_route_rules_hash(data, len, 0);
    bucket = hash & (mph->buckets_n - 1);
    pos = ngx_stream_trojan_route_rules_hash(data, len,
                                             mph->buckets[bucket].seed)
          % mph->size;
    slot = &mph->slots[pos];

    if (slot->len != len) {
        return NULL;
    }

    if (ngx_memcmp(mph->data + slot->offset, data, len) != 0) {
        return NULL;
    }

    return slot;
}


static uint32_t
ngx_stream_trojan_route_rules_hash(u_char *data, size_t len, uint32_t seed)
{
    size_t    i;
    uint32_t  hash;

    hash = 2166136261u ^ seed;

    for (i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 16777619u;
    }

    hash ^= hash >> 16;
    hash *= 0x7feb352du;
    hash ^= hash >> 15;
    hash *= 0x846ca68bu;
    hash ^= hash >> 16;

    return hash;
}


static ngx_uint_t
ngx_stream_trojan_route_rules_next_power(ngx_uint_t n)
{
    ngx_uint_t  p;

    p = 1;

    while (p < n) {
        p <<= 1;
    }

    return p;
}


static ngx_uint_t
ngx_stream_trojan_route_rules_ipv4_prefix(uint32_t mask)
{
    ngx_uint_t  n;

    n = 0;

    while (mask & 0x80000000u) {
        n++;
        mask <<= 1;
    }

    return n;
}


static uint32_t
ngx_stream_trojan_route_rules_ipv4_mask(ngx_uint_t prefix)
{
    if (prefix == 0) {
        return 0;
    }

    return 0xffffffffu << (32 - prefix);
}


#if (NGX_HAVE_INET6)
static ngx_uint_t
ngx_stream_trojan_route_rules_ipv6_prefix(u_char *mask)
{
    ngx_uint_t  i, n;
    u_char      bit;

    n = 0;

    for (i = 0; i < 16; i++) {
        for (bit = 0x80; bit != 0; bit >>= 1) {
            if ((mask[i] & bit) == 0) {
                return n;
            }

            n++;
        }
    }

    return n;
}


static void
ngx_stream_trojan_route_rules_ipv6_mask(u_char *dst, u_char *src,
    ngx_uint_t prefix)
{
    ngx_uint_t  i, bits;

    for (i = 0; i < 16; i++) {
        if (prefix >= 8) {
            dst[i] = src[i];
            prefix -= 8;
            continue;
        }

        if (prefix == 0) {
            dst[i] = 0;
            continue;
        }

        bits = 0xffu << (8 - prefix);
        dst[i] = (u_char) (src[i] & bits);
        prefix = 0;
    }
}
#endif


static int ngx_libc_cdecl
ngx_stream_trojan_cmp_domain_entries(const void *one, const void *two)
{
    ngx_stream_trojan_domain_build_entry_t  *first, *second;
    size_t                                   len;
    int                                      rc;

    first = (ngx_stream_trojan_domain_build_entry_t *) one;
    second = (ngx_stream_trojan_domain_build_entry_t *) two;

    len = ngx_min(first->key.len, second->key.len);
    rc = ngx_memcmp(first->key.data, second->key.data, len);

    if (rc != 0) {
        return rc;
    }

    if (first->key.len == second->key.len) {
        return 0;
    }

    return first->key.len < second->key.len ? -1 : 1;
}


static int ngx_libc_cdecl
ngx_stream_trojan_cmp_mph_buckets(const void *one, const void *two)
{
    ngx_stream_trojan_mph_bucket_sort_t  *first, *second;

    first = (ngx_stream_trojan_mph_bucket_sort_t *) one;
    second = (ngx_stream_trojan_mph_bucket_sort_t *) two;

    if (first->count == second->count) {
        return 0;
    }

    return first->count > second->count ? -1 : 1;
}


static int ngx_libc_cdecl
ngx_stream_trojan_cmp_ipv4_prefix(const void *one, const void *two)
{
    ngx_stream_trojan_ipv4_prefix_t  *first, *second;

    first = (ngx_stream_trojan_ipv4_prefix_t *) one;
    second = (ngx_stream_trojan_ipv4_prefix_t *) two;

    if (first->addr == second->addr) {
        return 0;
    }

    return first->addr < second->addr ? -1 : 1;
}


#if (NGX_HAVE_INET6)
static int ngx_libc_cdecl
ngx_stream_trojan_cmp_ipv6_prefix(const void *one, const void *two)
{
    ngx_stream_trojan_ipv6_prefix_t  *first, *second;

    first = (ngx_stream_trojan_ipv6_prefix_t *) one;
    second = (ngx_stream_trojan_ipv6_prefix_t *) two;

    return ngx_memcmp(first->addr, second->addr, 16);
}
#endif


static ngx_uint_t
ngx_stream_trojan_route_rules_ipv4_find(
    ngx_stream_trojan_ipv4_prefix_bucket_t *bucket, uint32_t addr)
{
    ngx_uint_t  left, right, mid;

    left = 0;
    right = bucket->nelts;

    while (left < right) {
        mid = (left + right) / 2;

        if (bucket->elts[mid].addr == addr) {
            return 1;
        }

        if (bucket->elts[mid].addr < addr) {
            left = mid + 1;
        } else {
            right = mid;
        }
    }

    return 0;
}


#if (NGX_HAVE_INET6)
static ngx_uint_t
ngx_stream_trojan_route_rules_ipv6_find(
    ngx_stream_trojan_ipv6_prefix_bucket_t *bucket, u_char *addr)
{
    ngx_uint_t  left, right, mid;
    int         rc;

    left = 0;
    right = bucket->nelts;

    while (left < right) {
        mid = (left + right) / 2;
        rc = ngx_memcmp(bucket->elts[mid].addr, addr, 16);

        if (rc == 0) {
            return 1;
        }

        if (rc < 0) {
            left = mid + 1;
        } else {
            right = mid;
        }
    }

    return 0;
}
#endif


static ngx_int_t
ngx_stream_trojan_route_rules_target_to_sockaddr(
    ngx_stream_trojan_addr_t *target, ngx_sockaddr_t *sockaddr)
{
    in_addr_t             addr;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    if (target == NULL || sockaddr == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(sockaddr, sizeof(ngx_sockaddr_t));

    switch (target->type) {

    case NGX_STREAM_TROJAN_ADDR_IPV4:
        if (target->host_len != 4) {
            return NGX_ERROR;
        }

        sin = &sockaddr->sockaddr_in;
        sin->sin_family = AF_INET;
        sin->sin_port = htons(target->port);
        ngx_memcpy(&sin->sin_addr, target->host, 4);
        return NGX_OK;

    case NGX_STREAM_TROJAN_ADDR_DOMAIN:
        addr = ngx_inet_addr(target->host, target->host_len);
        if (addr != INADDR_NONE) {
            sin = &sockaddr->sockaddr_in;
            sin->sin_family = AF_INET;
            sin->sin_port = htons(target->port);
            sin->sin_addr.s_addr = addr;
            return NGX_OK;
        }

#if (NGX_HAVE_INET6)
        sin6 = &sockaddr->sockaddr_in6;
        if (ngx_inet6_addr(target->host, target->host_len,
                           sin6->sin6_addr.s6_addr)
            == NGX_OK)
        {
            sin6->sin6_family = AF_INET6;
            sin6->sin6_port = htons(target->port);
            return NGX_OK;
        }
#endif

        return NGX_DECLINED;

#if (NGX_HAVE_INET6)
    case NGX_STREAM_TROJAN_ADDR_IPV6:
        if (target->host_len != 16) {
            return NGX_ERROR;
        }

        sin6 = &sockaddr->sockaddr_in6;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(target->port);
        ngx_memcpy(&sin6->sin6_addr, target->host, 16);
        return NGX_OK;
#endif

    default:
        return NGX_ERROR;
    }
}
