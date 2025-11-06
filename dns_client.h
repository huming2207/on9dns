#ifndef __DNS_CLIENT_H__
#define __DNS_CLIENT_H__

#include <stdint.h>
#include "lwip/ip_addr.h"

#define DNS_CLIENT_MAX_RECURSION 5

typedef enum {
    DNS_RECORD_A = 1,
    DNS_RECORD_AAAA = 28,
    DNS_RECORD_CNAME = 5,
} dns_record_type_t;

typedef enum {
    DNS_STATE_IDLE,
    DNS_STATE_SENDING,
    DNS_STATE_WAITING,
    DNS_STATE_CNAME,
    DNS_STATE_DONE,
    DNS_STATE_TIMEOUT,
    DNS_STATE_ERROR,
} dns_client_state_t;

typedef struct {
    dns_client_state_t state;
    int32_t sock;
    uint16_t transaction_id;
    char* hostname;
    ip_addr_t dns_server[3];
    ip_addr_t ip_addr;
    int32_t recursion_level;
    dns_record_type_t type;
    uint32_t timeout_ms;
    uint8_t buf[512];
} dns_client_t;

void dns_client_init(dns_client_t* client);
void dns_client_query(dns_client_t* client, const char* hostname, dns_record_type_t type, uint32_t timeout_ms);
dns_client_state_t dns_client_proc(dns_client_t* client);

#endif /* __DNS_CLIENT_H__ */