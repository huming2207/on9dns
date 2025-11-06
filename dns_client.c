#include <string.h>
#include <stdint.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "dns_client.h"


#define DNS_SERVER_PORT 53

// DNS header structure
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed));

// DNS question structure
struct dns_question {
    uint16_t qtype;
    uint16_t qclass;
} __attribute__((packed));

// DNS resource record structure
struct dns_answer {
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
} __attribute__((packed));

static void dns_client_state_sending(dns_client_t* client);
static void dns_client_state_waiting(dns_client_t* client);
static int32_t dns_parse_name(uint8_t* buf, int32_t len, int32_t* offset, char* name, int32_t name_len);

void dns_client_init(dns_client_t* client)
{
    memset(client, 0, sizeof(dns_client_t));
    client->state = DNS_STATE_IDLE;
    client->dns_server_count = 0;
    client->curr_dns_server_idx = 0;
    client->curr_dns_server_retry_cnt = 0;
    client->max_dns_server_retry_cnt = 3;
}

void dns_client_query(dns_client_t* client, const char* hostname, dns_record_type_t type, uint32_t timeout_ms)
{
    client->hostname = strdup(hostname);
    client->state = DNS_STATE_SENDING;
    client->transaction_id = (uint16_t)rand();
    client->recursion_level = 0;
    client->type = type;
    client->timeout_ms = timeout_ms;
    client->curr_dns_server_idx = 0;
    client->curr_dns_server_retry_cnt = 0;
}

dns_client_state_t dns_client_proc(dns_client_t* client)
{
    switch (client->state) {
        case DNS_STATE_SENDING:
            dns_client_state_sending(client);
            break;
        case DNS_STATE_WAITING:
            dns_client_state_waiting(client);
            break;
        case DNS_STATE_CNAME:
            client->recursion_level++;
            if (client->recursion_level >= DNS_CLIENT_MAX_RECURSION) {
                client->state = DNS_STATE_ERROR;
                close(client->sock);
            } else {
                client->state = DNS_STATE_SENDING;
            }
            break;
        case DNS_STATE_IDLE:
        case DNS_STATE_DONE:
        case DNS_STATE_TIMEOUT:
        case DNS_STATE_ERROR:
            // Nothing to do
            break;
        default:
            break;
    }
    return client->state;
}

static void dns_client_state_sending(dns_client_t* client)
{
    if (client->dns_server_count == 0 || client->dns_server_count > 3 || client->curr_dns_server_idx >= client->dns_server_count) {
        client->state = DNS_STATE_ERROR;
        close(client->sock);
        return;
    }

    // Create socket
    client->sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (client->sock < 0) {
        client->state = DNS_STATE_ERROR;
        close(client->sock);
        return;
    }

    // Set socket timeout
    struct timeval timeout;
    timeout.tv_sec = client->timeout_ms / 1000;
    timeout.tv_usec = (client->timeout_ms % 1000L) * 1000LL;
    setsockopt(client->sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // DNS server address
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(DNS_SERVER_PORT);
    dest_addr.sin_addr.s_addr = client->dns_server[client->curr_dns_server_idx].u_addr.ip4.addr;

    // Construct DNS query
    uint8_t* p = client->buf;
    struct dns_header* header = (struct dns_header*)p;
    header->id = htons(client->transaction_id);
    header->flags = htons(0x0100); // Standard query
    header->qdcount = htons(1);
    header->ancount = 0;
    header->nscount = 0;
    header->arcount = 0;
    p += sizeof(struct dns_header);

    // Question
    const char* hostname = client->hostname;
    while (*hostname) {
        const char* dot = strchr(hostname, '.');
        if (dot) {
            *p++ = dot - hostname;
            memcpy(p, hostname, dot - hostname);
            p += dot - hostname;
            hostname = dot + 1;
        } else {
            *p++ = strlen(hostname);
            memcpy(p, hostname, strlen(hostname));
            p += strlen(hostname);
            break;
        }
    }
    *p++ = 0x00;

    struct dns_question* question = (struct dns_question*)p;
    question->qtype = htons(client->type);
    question->qclass = htons(1); // IN
    p += sizeof(struct dns_question);

    // Send DNS query
    if (sendto(client->sock, client->buf, p - client->buf, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
        client->state = DNS_STATE_ERROR;
        close(client->sock);
        return;
    }

    client->state = DNS_STATE_WAITING;
}

static void dns_client_state_waiting(dns_client_t* client)
{
    const int32_t len = recv(client->sock, client->buf, sizeof(client->buf), 0);

    if (len < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            client->curr_dns_server_retry_cnt++;
            if (client->curr_dns_server_retry_cnt > client->max_dns_server_retry_cnt) {
                client->curr_dns_server_retry_cnt = 0;
                client->curr_dns_server_idx++;
                if (client->curr_dns_server_idx >= client->dns_server_count) {
                    client->state = DNS_STATE_ERROR; // All servers tried and failed
                    close(client->sock);
                } else {
                    client->state = DNS_STATE_SENDING; // Move to next server
                }
            } else {
                client->state = DNS_STATE_SENDING; // Retry with the same server
            }
        } else {
            client->state = DNS_STATE_ERROR;
            close(client->sock);
        }
        return;
    }
    client->curr_dns_server_retry_cnt = 0;
    client->curr_dns_server_idx = 0;

    if (len < sizeof(struct dns_header)) {
        client->state = DNS_STATE_ERROR;
        close(client->sock);
        return;
    }

    const struct dns_header* header = (struct dns_header*)client->buf;
    if (ntohs(header->id) != client->transaction_id) {
        // Not our transaction, ignore
        return;
    }

    if ((ntohs(header->flags) & 0xf) != 0) {
        // Error
        client->state = DNS_STATE_ERROR;
        close(client->sock);
        return;
    }

    int32_t offset = sizeof(struct dns_header);
    char name[256] = { 0 };

    // Skip question section
    for (int i = 0; i < ntohs(header->qdcount); i++) {
        if (dns_parse_name(client->buf, len, &offset, name, sizeof(name)) != 0) {
            client->state = DNS_STATE_ERROR;
            close(client->sock);
            return;
        }
        if (offset + sizeof(struct dns_question) > len) {
            client->state = DNS_STATE_ERROR;
            close(client->sock);
            return;
        }
        offset += sizeof(struct dns_question);
    }

    // Parse answer section
    for (int i = 0; i < ntohs(header->ancount); i++) {
        if (dns_parse_name(client->buf, len, &offset, name, sizeof(name)) != 0) {
            client->state = DNS_STATE_ERROR;
            close(client->sock);
            return;
        }

        if (offset + sizeof(struct dns_answer) > len) {
            client->state = DNS_STATE_ERROR;
            close(client->sock);
            return;
        }
        const struct dns_answer* answer = (struct dns_answer*)(client->buf + offset);
        offset += sizeof(struct dns_answer);

        const uint16_t type = ntohs(answer->type);
        const uint16_t rdlength = ntohs(answer->rdlength);

        if (offset + rdlength > len) {
            client->state = DNS_STATE_ERROR;
            close(client->sock);
            return;
        }

        if (type == DNS_RECORD_A && rdlength == 4) {
            client->ip_addr.type = IPADDR_TYPE_V4;
            memcpy(&client->ip_addr.u_addr.ip4, client->buf + offset, 4);
            client->state = DNS_STATE_DONE;
            close(client->sock);
            return;
        } else if (type == DNS_RECORD_AAAA && rdlength == 16) {
            client->ip_addr.type = IPADDR_TYPE_V6;
            memcpy(&client->ip_addr.u_addr.ip6, client->buf + offset, 16);
            client->state = DNS_STATE_DONE;
            close(client->sock);
            return;
        } else if (type == DNS_RECORD_CNAME) {
            char cname[256] = { 0 };
            int32_t cname_offset = offset;
            if (dns_parse_name(client->buf, len, &cname_offset, cname, sizeof(cname)) != 0) {
                client->state = DNS_STATE_ERROR;
                close(client->sock);
                return;
            }
            free(client->hostname);
            client->hostname = strdup(cname);
            client->state = DNS_STATE_CNAME;
            close(client->sock);
            return;
        }
        offset += rdlength;
    }
}

static int32_t dns_parse_name(uint8_t* buf, int32_t len, int32_t* offset, char* name, int32_t name_len) {
    int32_t pos = 0;
    int32_t jumped = 0;
    int32_t jumps = 0;
    int32_t initial_offset = *offset;

    while (*offset < len && buf[*offset] != 0) {
        if (pos >= name_len - 1) {
            return -1;
        }
        if ((buf[*offset] & 0xc0) == 0xc0) {
            if (jumps++ > 10) return -1; // Max jumps
            if (*offset + 1 >= len) return -1; // Out of bounds
            if (!jumped) {
                initial_offset = *offset + 2;
                jumped = 1;
            }
            *offset = (ntohs(*(uint16_t*)(buf + *offset)) & 0x3fff);

        } else {
            const int32_t label_len = buf[*offset];
            (*offset)++;
            if (*offset + label_len >= len) return -1; // Out of bounds
            if (pos > 0) {
                name[pos++] = '.';
            }
            if (pos + label_len >= name_len) {
                return -1;
            }
            memcpy(name + pos, buf + *offset, label_len);
            pos += label_len;
            *offset += label_len;
        }
    }
    if (*offset >= len) return -1; // Out of bounds
    name[pos] = '\0';
    if (jumped) {
        *offset = initial_offset;
    } else {
        (*offset)++;
    }
    return 0;
}