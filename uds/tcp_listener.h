#ifndef TCP_LISTENER_H
#define TCP_LISTENER_H

#include "uds_engine.h"

/* TCP listener configuration */
#define TCP_PORT 9556
#define TCP_BUFFER_SIZE 4096
#define TCP_BACKLOG 5

/* Function prototypes */
int tcp_listener_init(void);
int tcp_listener_run(uds_state_t *state);
void tcp_listener_stop(void);

#endif /* TCP_LISTENER_H */
