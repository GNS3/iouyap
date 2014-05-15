
#ifndef IOUYAP_H_
#define IOUYAP_H_

#include <netinet/in.h>
#include <errno.h>
#include <sys/un.h>


#define CONFIG_FILE           "iouyap.ini"
#define NETMAP_FILE           "NETMAP"
#define NETIO_DIR_PREFIX      "/tmp/netio"
#define BASE_PORT             49000
#define DEFAULT_STRICT_MODE   0

#define MAX_MTU               0x1000      // according to IOU
#define MAX_PORTS             256

#define NO_FD                 -1

// IOU header
/* offsets */
#define IOU_DST_IDS           0
#define IOU_SRC_IDS           2
#define IOU_DST_PORT          4
#define IOU_SRC_PORT          5
#define IOU_MSG_TYPE          6
#define IOU_CHANNEL           7
/* sizes */
#define IOU_HDR_SIZE          8
#define IOU_IDS_SIZE          2
#define IOU_PORT_SIZE         1
#define IOU_MSG_SIZE          1
#define IOU_CHANNEL_SIZE      1
/* values */
#define IOU_MSG_TYPE_FREE     0
#define IOU_MSG_TYPE_DATA     1

/* IOU nodes */
/* bit offsets */
#define IOU_IDS_ID                      10
#define IOU_IDS_SUBID                   14
#define IOU_IDS_SUBID_PRESENT           15
/* bit lengths */
#define IOU_IDS_ID_LEN                  11
#define IOU_IDS_SUBID_LEN               4
#define IOU_IDS_SUBID_PRESENT_LEN       1

/* IOU ports */
/* bit offsets */
#define IOU_PORT_UNIT                   7
#define IOU_PORT_BAY                    3
/* bit lengths */
#define IOU_PORT_UNIT_LEN               4
#define IOU_PORT_BAY_LEN                4

/* Not everyone has UNIX_PATH_MAX */
#ifndef UNIX_PATH_MAX
struct sockaddr_un sizecheck;
#define UNIX_PATH_MAX sizeof(sizecheck.sun_path)
#endif

/* Logging levels */
enum {LOG_QUIET, LOG_BASIC, LOG_EXTENDED, LOG_NOISY, LOG_CRAZY};


#define STMT( code )  do { code } while (0)

#ifndef DEBUG_LOG
#  ifdef DEBUG
#    define DEBUG_LOG 1
#  else
#    define DEBUG_LOG 0
#  endif
#else
#  define DEBUG_LOG 1
#endif

#if DEBUG_LOG
#define log_prefix() \
        STMT( fprintf(stderr, "%s:%s:%d: ", \
                        __FILE__, __func__, __LINE__); )
#else
extern char *program_invocation_name;
#define log_prefix() \
        STMT( fprintf(stderr, "%s: ", program_invocation_name); )
#endif

#define log_msg(msg) \
    STMT( log_fmt("%s\n", msg); )
#define log_fmt(fmt, ...) \
    STMT( log_prefix(); fprintf(stderr, fmt, ## __VA_ARGS__); )

#define log_error_en(en, msg) \
    STMT( errno = en; log_error(msg); )
#define log_error(msg) \
    STMT( log_prefix(); perror(msg); )

#define debug_log(msg) \
    STMT( if (DEBUG_LOG) log_msg(msg); )
#define debug_log_fmt(fmt, ...) \
    STMT( if (DEBUG_LOG) log_fmt(fmt, ## __VA_ARGS__); )

#define die(msg) \
    STMT( log_msg(msg); exit(EXIT_FAILURE); )
#define die_fmt(fmt, ...) \
    STMT( log_fmt(fmt, ## __VA_ARGS__); exit(EXIT_FAILURE); )

#define fatal_error_en(en, msg) \
    STMT( log_error_en(en, msg); exit(EXIT_FAILURE); )
#define fatal_error(msg) \
    STMT( log_error(msg); exit(EXIT_FAILURE); )


typedef struct list_node
{
  void *data;
  struct list_node *next;
} list_node_t;

typedef struct
{
  list_node_t *first;
  size_t size;
  int ref_cnt;
} list_head_t;

typedef struct
{
  unsigned short id;
  unsigned char subid;
  unsigned char subid_present;
} appl_id_t;

typedef struct port
{
  unsigned char bay;
  unsigned char unit;
} port_t;

typedef struct
{
  appl_id_t ids;
  port_t port;
  struct in_addr addr;
} node_t;

typedef struct
{
  node_t dst_node;
  node_t src_node;
  unsigned char msg_type;
  unsigned char channel;
} iou_hdr_t;

typedef struct
{
  unsigned char header[IOU_HDR_SIZE];
  int sfd;
  union
  {
    struct sockaddr sa;
    struct sockaddr_in sa_in;
    struct sockaddr_un sa_un;
  };
  socklen_t sa_len;
} iou_node_t;

typedef struct
{
  list_head_t *segment;
  int sfd;

  union
  {
    struct sockaddr sa;
    struct sockaddr_in sa_in;
    struct sockaddr_un sa_un;
  };
  socklen_t sa_len;

  pthread_t thread_id;
  int iou_port;
  iou_node_t *nodes;
} foreign_port_t;


extern int yap_appl_id;
extern unsigned int yap_verbose;
extern foreign_port_t *port_table;
extern unsigned char pack_port (port_t port);
extern port_t unpack_port (unsigned char port);


#endif /* !IOUYAP_H_ */


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
