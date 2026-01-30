#ifndef CAN_LISTENER_H
#define CAN_LISTENER_H

#include "uds_engine.h"

/* CAN configuration */
#define CAN_INTERFACE "vcan0"

/* UDS CAN IDs */
#define CAN_ID_UDS_BROADCAST 0x7DF
#define CAN_ID_UDS_ECU_MIN   0x7E0
#define CAN_ID_UDS_ECU_MAX   0x7E7
#define CAN_ID_UDS_RESPONSE  0x7E8

/* Function prototypes */
int can_listener_init(void);
void *can_listener_thread(void *arg);
void can_listener_stop(void);

#endif /* CAN_LISTENER_H */
