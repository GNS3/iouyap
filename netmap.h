
#ifndef NETMAP_H_
#define NETMAP_H_

#include "iouyap.h"


#define HT_SIZE     200

#define ID_MIN      1
#define ID_MAX      1024
#define SUBID_MIN   0
#define SUBID_MAX   15
#define PORT_MIN    0
#define PORT_MAX    255
#define BAY_MIN     0
#define BAY_MAX     15
#define UNIT_MIN    0
#define UNIT_MAX    15


extern node_t *iou_node_tmp;
extern FILE *yyin;

int parse_netmap (char *file);
int add_node (void);
void end_segment (void);
void delete_chain (list_head_t *chain);


#endif /* NETMAP_H_ */



/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 2
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=2 expandtab:
 * :indentSize=2:tabSize=2:noTabs=true:
 */
