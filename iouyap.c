/*
 *   This file is part of iouyap, a program to bridge IOU with
 *   network interfaces.
 *
 *   Copyright (C) 2013, 2014  James E. Carpenter
 *
 *   iouyap is free software: you can redistribute it and/or modify it
 *   under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   iouyap is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netdb.h>
#include <iniparser.h>
#include <net/if_arp.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <sys/time.h>
#include <limits.h>
#include <sys/file.h>
#include <ctype.h>

#include "iouyap.h"
#include "netmap.h"
#include "config.h"


extern char *program_invocation_short_name;
extern char *program_invocation_name;

int yap_appl_id = -1;
unsigned int yap_verbose = LOG_BASIC;
dictionary *yap_config = NULL;
foreign_port_t *port_table = NULL;


static int
set_socket_directory (char *dir)
{
  return snprintf (dir, UNIX_PATH_MAX, "%s%u", NETIO_DIR_PREFIX, getuid ());
}


static int
set_socket_filename (char *name, unsigned int appl_id)
{
  char dir[UNIX_PATH_MAX];

  set_socket_directory (dir);
  return snprintf (name, UNIX_PATH_MAX, "%s/%u", dir, appl_id);
}


static pid_t
get_socket_lock (const char *name)
{
  char semaphore[FILENAME_MAX];
  int fd;
  struct flock fl;
  int e;

  if (strlen (name) < 1)
    {
      errno = EINVAL;
      return -1;
    }

  snprintf (semaphore, sizeof semaphore, "%s.lck", name);
  if ((fd = open (semaphore, O_RDONLY)) < 0)
    return -1;

  fl.l_type = F_WRLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  fl.l_len = 0;
  fl.l_pid = getpid ();

  if (fcntl (fd, F_GETLK, &fl) < 0)
    {
      e = errno;
      close (fd);
      errno = e;
      return -1;
    }

  close (fd);
  return fl.l_pid;
}


static int
unlock_socket (int fd, const char *name)
{
  char semaphore[FILENAME_MAX];
  int result;
  int e;

  if (fd < 0)
    {
      errno = EINVAL;
      return -1;
    }

  snprintf (semaphore, sizeof semaphore, "%s.lck", name);

  /* Unlinking before close avoids a race condition where we
   * could accidentally delete the next lock file.
   */
  result = unlink (semaphore);
  e = errno;
  close (fd);
  errno = e;

  return result;
}


static int
lock_socket (const char *name)
{
  char semaphore[FILENAME_MAX];
  int fd;
  char pid[12];
  int pid_len;
  struct flock fl;
  int e;

  if (strlen (name) < 1)
    {
      errno = EINVAL;
      return -1;
    }

  snprintf (semaphore, sizeof semaphore, "%s.lck", name);

  // Either find a lock-file or create a new one
  if ((fd = open (semaphore, O_WRONLY)) < 0 && errno == ENOENT)
    fd = open (semaphore, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR);
  if (fd < 0)
    return -1;

  fl.l_type = F_WRLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  fl.l_len = 0;

  if (fcntl (fd, F_SETLK, &fl) < 0)
    {
      close (fd);
      errno = EADDRINUSE;
      return -1;
    }

  // We have the lock. Wipe out the file and put our PID in it.
  ftruncate (fd, 0);
  pid_len = snprintf (pid, sizeof(pid), "%ld\n", (long) getpid ());
  if (write (fd, pid, pid_len) == -1)
    {
      e = errno;
      // Something is wrong. Roll back.
      unlock_socket (fd, name);
      errno = e;
      return -1;
    }

  return fd;
}


/* getbits:  get n bits from position p
 *    (liberated from K&R2, p. 49)
 */
static unsigned int
getbits (unsigned int x, int p, int n)
{
  return (x >> (p + 1 - n)) & ~(~0 << n);
}


static unsigned int
setbits (unsigned int x, int p, int n, unsigned int y)
{
  return ((x & ~(~(~0 << n) << (p + 1 - n)))
          | ((y & ~(~0 << n)) << (p + 1 - n)));
}


appl_id_t
unpack_ids (unsigned short appl_id)
{
  appl_id_t i;

  i.id = getbits(appl_id, IOU_IDS_ID, IOU_IDS_ID_LEN);
  i.subid = getbits(appl_id, IOU_IDS_SUBID, IOU_IDS_SUBID_LEN);
  i.subid_present = getbits(appl_id, IOU_IDS_SUBID_PRESENT,
                            IOU_IDS_SUBID_PRESENT_LEN);

  return i;
}


port_t
unpack_port (unsigned char port)
{
  port_t p;

  p.unit = getbits(port, IOU_PORT_UNIT, IOU_PORT_UNIT_LEN);
  p.bay = getbits(port, IOU_PORT_BAY, IOU_PORT_BAY_LEN);

  return p;
}


unsigned short
pack_ids (appl_id_t appl_id)
{
  unsigned short i = 0;

  i = setbits (i, IOU_IDS_ID, IOU_IDS_ID_LEN, appl_id.id);
  i = setbits (i, IOU_IDS_SUBID, IOU_IDS_SUBID_LEN, appl_id.subid);
  i = setbits (i, IOU_IDS_SUBID_PRESENT, IOU_IDS_SUBID_PRESENT_LEN,
               appl_id.subid_present);

  return i;
}


unsigned char
pack_port (port_t port)
{
  unsigned char p = 0;

  p = setbits (p, IOU_PORT_BAY, IOU_PORT_BAY_LEN, port.bay);
  p = setbits (p, IOU_PORT_UNIT, IOU_PORT_UNIT_LEN, port.unit);

  return p;
}


void
parse_iou_hdr (iou_hdr_t *iou_hdr, unsigned char *iou_hdr_buf)
{
  unsigned short dst_node;
  unsigned short src_node;
  unsigned char dst_port;
  unsigned char src_port;

  /* destination node */
  dst_node = ntohs (*(unsigned short *) &iou_hdr_buf[IOU_DST_IDS]);
  iou_hdr->dst_node.ids = unpack_ids (dst_node);

  /* source node */
  src_node = ntohs (*(unsigned short *) &iou_hdr_buf[IOU_SRC_IDS]);
  iou_hdr->src_node.ids = unpack_ids (src_node);

  /* destination port */
  dst_port = iou_hdr_buf[IOU_DST_PORT];
  iou_hdr->dst_node.port = unpack_port (dst_port);

  /* source port */
  src_port = iou_hdr_buf[IOU_SRC_PORT];
  iou_hdr->src_node.port = unpack_port (src_port);

  /* message type & channel */
  iou_hdr->msg_type = iou_hdr_buf[IOU_MSG_TYPE];
  iou_hdr->channel = iou_hdr_buf[IOU_CHANNEL];
}


void
build_iou_hdr (unsigned char *buf, iou_hdr_t iou_hdr)
{
  appl_id_t dst_ids = iou_hdr.dst_node.ids;
  appl_id_t src_ids = iou_hdr.src_node.ids;
  port_t dst_port = iou_hdr.dst_node.port;
  port_t src_port = iou_hdr.src_node.port;
  unsigned short n;

  /* destination id */
  n = htons (pack_ids (dst_ids));
  memcpy(&buf[IOU_DST_IDS], (unsigned char *)&n, IOU_IDS_SIZE);
  /* source id */
  n = htons (pack_ids (src_ids));
  memcpy(&buf[IOU_SRC_IDS], (unsigned char *)&n, IOU_IDS_SIZE);

  /* destination port */
  buf[IOU_DST_PORT] = pack_port (dst_port);
  /* source port */
  buf[IOU_SRC_PORT] = pack_port (src_port);

  /* message type */
  buf[IOU_MSG_TYPE] = iou_hdr.msg_type;
  /* channel number */
  buf[IOU_CHANNEL] = iou_hdr.channel;
}


static int
get_iou_udp_port (int port)
{
  return ini_getint_default_def ("base_port", BASE_PORT) + port;
}


static int
write_pcap_header (int fd, int snaplen, int linktype)
{
  struct pcap_file_header header;

  header.magic = 0xa1b2c3d4;
  header.version_major = 2;
  header.version_minor = 4;
  header.thiszone = 0;
  header.sigfigs = 0;
  header.snaplen = snaplen;
  header.linktype = linktype;

  if (write (fd, &header, sizeof header) != sizeof header)
    return -1;
  return 0;
}

static int
write_pcap_frame (int fd, const unsigned char *packet, size_t len,
                  size_t caplen, int linktype)
{
  size_t count;
  struct pcap_pkthdr pcap_header;
  size_t hdr_len = sizeof pcap_header;
  unsigned char buf[MAX_MTU + hdr_len];
  struct timeval ts;

  if (caplen > MAX_MTU)
     return -1;

  gettimeofday (&ts, 0);
  pcap_header.tv_sec = ts.tv_sec;
  pcap_header.tv_usec = ts.tv_usec;

  if (len < caplen)
    caplen = len;
  pcap_header.caplen = caplen;
  pcap_header.len = len;

  memcpy (buf, &pcap_header, hdr_len);
  memcpy (&buf[hdr_len], packet, caplen);

  count = caplen + hdr_len;
  if (write (fd, &buf, count) != count)
    return -1;
  return 0;
}


static void *
foreign_listener (void *arg)
{
  foreign_port_t *port = arg;
  int segment_size;
  ssize_t bytes_received, bytes_sent;
  iou_node_t *nodes;
  unsigned char buf[IOU_HDR_SIZE + MAX_MTU]; // TODO: may already include HDR
  int i, j;

  /* segment size, minus us */
  segment_size = port->segment->size - 1;
  nodes = port->nodes;

  if (yap_verbose >= LOG_EXTENDED)
    log_fmt ("foreign listener for %d:%d started (sfd=%d)\n",
             yap_appl_id, port->iou_port, port->sfd);

  for (;;)
    {
      /* Put received bytes after the (absent) IOU header */
      bytes_received = read (port->sfd, &buf[IOU_HDR_SIZE], MAX_MTU);

      if (bytes_received <= 0)
        {
          /* When tunneling, because our sends are asynchronous, we
           * can get errors here from ICMP packets for UDP packets we
           * sent earlier.
           */
          switch (errno)
            {
            case ECONNREFUSED:
              if (yap_verbose >= LOG_NOISY)
                log_error ("read");
              continue;
            default:
              log_error ("read");
              goto shutdown;
            }
        }

      if (yap_verbose >= LOG_CRAZY)
        debug_log_fmt ("received %zd bytes (sfd=%d)\n",
                       bytes_received, port->sfd);


      if (port->span_sfd != NO_FD)
        write (port->span_sfd, &buf[IOU_HDR_SIZE], bytes_received);


      if (port->pcap_fd != NO_FD)
        {
          write_pcap_frame (port->pcap_fd, &buf[IOU_HDR_SIZE],
                            bytes_received, port->pcap_caplen,
                            port->pcap_linktype);
        }


      /* Add the length of the IOU header we'll be sending */
      bytes_received += IOU_HDR_SIZE;

      /* Send the packet to the IOU node(s) in our segment. For each
       * node, we copy the pre-calculated IOU header into the
       * beginning of the buffer before sending.
       */
      for (i = 0; i < segment_size; i++)
        {
          memcpy (buf, &nodes[i].header, sizeof nodes[i].header);
          bytes_sent = sendto (nodes[i].sfd, buf, bytes_received,
                               0, &nodes[i].sa, nodes[i].sa_len);

          /* Make sure everything went out. Certain errors, like a
           * socket that hasn't been created yet, should be ignored.
           * Others we can consider fatal and so we remove the node
           * from the IOU segment.
           */
          if (bytes_sent != bytes_received)
            {
              if (bytes_sent != -1)  /* no error, shouldn't happen */
                {
                  log_fmt ("sendto() only sent %zd of %zd bytes!"
                           " (sfd=%d)\n", bytes_sent,
                           bytes_received, port->sfd);
                  continue;
                }

              switch (errno)
                {
                case ENOENT:   /* Socket file doesn't exist */
                case ECONNREFUSED:
                  if (yap_verbose >= LOG_NOISY)
                    log_error ("sendto");
                  continue;
                default:
                  log_error ("sendto");
                  break;
                }

              /* Remove the offending node */
              segment_size--;
              for (j = i; j < segment_size; j++)
                nodes[j] = nodes[j + 1];
              i--;    /* redo (now with the next node) */
              log_msg ("offending node removed");

              if (segment_size == 0)
                {
                  log_msg ("no nodes left!");
                  goto shutdown;
                }
            }
        }
    }

shutdown:
  log_msg ("Thread shutting down because of errors");
  return NULL;
}


static void *
iou_listener (void *arg)
{
  int sfd = *(int *) arg;
  ssize_t bytes_received, bytes_sent;
  unsigned char buf[IOU_HDR_SIZE + MAX_MTU]; // TODO: may already include HDR
  unsigned int port;
#ifdef DEBUG
  iou_hdr_t iou_hdr;
#endif

  if (yap_verbose >= LOG_EXTENDED)
    log_fmt ("IOU listener for ID %d started (sfd=%d)\n", yap_appl_id, sfd);

  for (;;)
    {
      /* This receives from an IOU instance */
      bytes_received = read (sfd, buf, IOU_HDR_SIZE + MAX_MTU);
      if (bytes_received <= 0)
        {
          log_error ("read");
          break;
        }

#ifdef DEBUG
      parse_iou_hdr (&iou_hdr, buf);
      if (iou_hdr.dst_node.ids.id != yap_appl_id
          || iou_hdr.dst_node.ids.subid_present == 1)
        {
          log_msg ("Packet is not for us!");
          continue;
        }
#endif

      /* Get the port number we were addressed as */
      port = buf[IOU_DST_PORT];

      if (yap_verbose >= LOG_CRAZY)
        debug_log_fmt ("received %zd bytes for port %d (sfd=%d)\n",
                       bytes_received, port, sfd);

      if (bytes_received <= IOU_HDR_SIZE)
          continue; 

      /* Send on the packet, minus the IOU header */
      bytes_received -= IOU_HDR_SIZE;


      if (port_table[port].span_sfd != NO_FD)
        write (port_table[port].span_sfd, &buf[IOU_HDR_SIZE],
               bytes_received);


      if (port_table[port].pcap_fd != NO_FD)
        {
          write_pcap_frame (port_table[port].pcap_fd, &buf[IOU_HDR_SIZE],
                            bytes_received, port_table[port].pcap_caplen,
                            port_table[port].pcap_linktype);
        }


      bytes_sent = write (port_table[port].sfd, &buf[IOU_HDR_SIZE],
                          bytes_received);

      if (bytes_sent != bytes_received)
        {
          if (bytes_sent != -1)  /* no error, shouldn't happen */
            {
              log_fmt ("write() only sent %zd of %zd bytes! (sfd=%d)\n",
                       bytes_sent, bytes_received, sfd);
              continue;
            }

          switch (errno)
            {
//            case ENOENT:
//              if (yap_verbose >= LOG_NOISY)
//                log_msg ("ENOENT");
//              continue;
            case EBADF:  /* Bad file descriptor */
              /* This error is normal if no foreign port is configured */
              if (port_table[port].sfd == NO_FD)
                {
                  if (yap_verbose >= LOG_NOISY)
                    log_fmt ("Discarding packet from port %d. "
                             "No foreign port configured.\n", port);
                  continue;
                }
              break;
            case ECONNREFUSED:
              if (yap_verbose >= LOG_NOISY)
                log_msg ("ECONNREFUSED");
              continue;
            case ENOTCONN:
              if (yap_verbose >= LOG_NOISY)
                log_msg ("ENOTCONN");

              /* Try to (re-)connect */
              if (!connect (port_table[port].sfd, &port_table[port].sa,
                            port_table[port].sa_len))
                continue;

              /* We couldn't connect. Some connect errors are okay.
                 We'll just try again later. */
              switch (errno)
                {
                case ENOENT:
                case ECONNREFUSED:
                  continue;
                default:
                  log_error ("connect");
                  goto shutdown;
                }
              break;
            default:
              break;
            }
          log_error ("Couldn't write to foreign port");
          goto shutdown;
        }
    }

shutdown:
  log_msg ("Thread shutting down because of errors");
  return NULL;
}


static void
open_eth_dev (foreign_port_t * port, char *dev)
{
  int sfd;
  struct ifreq ifr;

  struct sockaddr_ll sa;
  struct packet_mreq mreq;

  if (strlen (dev) >= IFNAMSIZ)
    die ("too big");

  if (yap_verbose >= LOG_EXTENDED)
    log_fmt ("Trying to open %s\n", dev);

  /* open socket */
  sfd = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
  if (sfd == -1)
    fatal_error ("socket");

  /* get interface number */
  memset (&ifr, 0, sizeof ifr);
  strcpy (ifr.ifr_name, dev);
  if (ioctl (sfd, SIOCGIFINDEX, &ifr) == -1)
    fatal_error ("ioctl");

  if (yap_verbose >= LOG_NOISY)
    log_fmt ("ifr_name=%s, ifr_ifindex=%d\n", ifr.ifr_name, ifr.ifr_ifindex);

  /* bind */
  memset (&sa, 0, sizeof sa);
  sa.sll_family = AF_PACKET;
  sa.sll_ifindex = ifr.ifr_ifindex;
  if (bind (sfd, (struct sockaddr *) &sa, sizeof sa) == -1)
    fatal_error ("bind");

  /* set promiscuous mode */
  memset (&mreq, 0, sizeof mreq);
  mreq.mr_ifindex = ifr.ifr_ifindex;
  mreq.mr_type = PACKET_MR_PROMISC;
  if (setsockopt (sfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                  &mreq, sizeof mreq) == -1)
    fatal_error ("setsockopt");

  if (yap_verbose >= LOG_BASIC)
    log_fmt ("%s opened (sfd=%d)\n", ifr.ifr_name, sfd);

  port->sfd = sfd;
}


static void
open_tap_dev (foreign_port_t * port, char *dev)
{
  struct ifreq ifr;
  int sfd;

  if (strlen (dev) >= IFNAMSIZ)
    die ("too big");

  if (yap_verbose >= LOG_EXTENDED)
    log_fmt ("Trying to open %s\n", dev);

  if ((sfd = open (TAP_DEV, O_RDWR)) < 0)
    fatal_error ("open");

  memset (&ifr, 0, sizeof ifr);
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

  if (*dev)
    strcpy (ifr.ifr_name, dev);
  if (ioctl (sfd, TUNSETIFF, (void *) &ifr) < 0)
    fatal_error ("ioctl");
  strcpy (dev, ifr.ifr_name);

  if (yap_verbose >= LOG_BASIC)
    log_fmt ("%s opened (sfd=%d)\n", ifr.ifr_name, sfd);

  port->sfd = sfd;
}


static void
open_span_dev (foreign_port_t * port, char *dev)
{
  struct ifreq ifr;
  int sfd;

  int sock;
  struct {
    struct nlmsghdr  nh;
    struct ifinfomsg ifinfo;
    char             attrbuf[512];
  } req;
  struct rtattr *rta;
  unsigned int mtu = 68;  // too small for IPv6, which is good here
  int rtnetlink_sk;

  if (strlen (dev) >= IFNAMSIZ)
    die ("too big");

  if (yap_verbose >= LOG_EXTENDED)
    log_fmt ("Trying to open %s\n", dev);

  if ((sfd = open (TAP_DEV, O_WRONLY)) < 0)
    fatal_error ("open");

  memset (&ifr, 0, sizeof ifr);
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_MULTI_QUEUE;

  if (*dev)
    strcpy (ifr.ifr_name, dev);
  if (ioctl (sfd, TUNSETIFF, (void *) &ifr) < 0)
    fatal_error ("TUNSETIFF ioctl");

  if (yap_verbose >= LOG_BASIC)
    log_fmt ("%s opened (sfd=%d)\n", ifr.ifr_name, sfd);

  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (ioctl (sock, SIOCGIFINDEX, (void *) &ifr) < 0)
    fatal_error ("SIOCGIFINDEX ioctl");

  rtnetlink_sk = socket (AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  memset (&req, 0, sizeof req);
  req.nh.nlmsg_len = NLMSG_LENGTH (sizeof req.ifinfo);
  req.nh.nlmsg_flags = NLM_F_REQUEST;
  req.nh.nlmsg_type = RTM_SETLINK;
  req.ifinfo.ifi_family = AF_UNSPEC;
  req.ifinfo.ifi_index = ifr.ifr_ifindex;
  req.ifinfo.ifi_change = 0xffffffff;
  req.ifinfo.ifi_flags = IFF_UP | IFF_PROMISC | IFF_NOARP;
  rta = (struct rtattr *)(((char *) &req) + NLMSG_ALIGN (req.nh.nlmsg_len));
  rta->rta_type = IFLA_MTU;
  rta->rta_len = RTA_LENGTH (sizeof (unsigned int));
  req.nh.nlmsg_len = NLMSG_ALIGN (req.nh.nlmsg_len) + RTA_LENGTH (sizeof mtu);
  memcpy (RTA_DATA (rta), &mtu, sizeof mtu);
  send (rtnetlink_sk, &req, req.nh.nlmsg_len, 0);
  close (rtnetlink_sk);

  port->span_sfd = sfd;
}


static void
open_pcap_file (foreign_port_t * port, char *file, int no_hdr, int overwrite)
{
  int fd;

  if ((fd = open (file, O_CREAT | O_WRONLY | O_APPEND, S_IRUSR | S_IWUSR)) < 0)
    fatal_error ("open");
    
  if( getuid() != geteuid() )
    if( fchown(fd, getuid (), -1) )
        fatal_error ("fchown");

  /* If we can get an exclusive lock (without blocking) then check to see
   * if the file is empty. Write a pcap header if it is.
   */
  if (!no_hdr || overwrite)
    {
      if (flock (fd, LOCK_EX | LOCK_NB) == 0)
        {
          if (overwrite)
            ftruncate (fd, 0);
          if (!no_hdr && lseek (fd, 0, SEEK_END) == 0)
            {
              if (write_pcap_header (fd, port->pcap_caplen,
                                     port->pcap_linktype) < 0)
                {
                  fatal_error ("write_pcap_header");
                }
            }
        }
      else if (errno == EWOULDBLOCK)
        {
          if (overwrite)
            log_fmt ("Can't overwrite %s. Somebody has a lock.\n", file);
        }
      else
        {
          close (fd);
          fatal_error ("flock");
        }
    }
  /* For normal operation we hold a shared lock */
  if (flock (fd, LOCK_SH) < 0)
    {
      close (fd);
      fatal_error ("flock");
    }

  port->pcap_fd = fd;
}


static void
open_pcap_pipe (foreign_port_t * port, char *file, int no_hdr)
{
  int fd;
  int new_pipe = 0;

  /* Create the named pipe. Whoever creates it has to clean up. */
  if (mkfifo (file, S_IRUSR | S_IWUSR) == 0)
    {
      port->pcap_fifo = file;
      new_pipe = 1;
    }
  else if (errno != EEXIST)
    {
      fatal_error ("mkfifo");
    }

  // O_RDWR allows us to open the pipe without any readers attached
  if ((fd = open (file, O_RDWR)) < 0)
    {
      fatal_error ("open");
    }

  /* If we created the pipe then we should normally be the one to write the
   * header.
   */
  if (!no_hdr && new_pipe)
    {
      if (flock (fd, LOCK_EX | LOCK_NB) == 0)
        {
          if (write_pcap_header (fd, port->pcap_caplen,
                                 port->pcap_linktype) < 0)
            {
              fatal_error ("write_pcap_header");
            }
        }
      else if (errno == EWOULDBLOCK)
        {
          log_msg ("Couldn't write pcap header to pipe we created! Locked.");
        }
      else
        {
          close (fd);
          fatal_error ("flock");
        }
    }

  /* For normal operation we hold a shared lock */
  if (flock (fd, LOCK_SH) < 0)
    {
      close (fd);
      fatal_error ("flock");
    }

  port->pcap_fd = fd;
}


static void
open_tunnel_uds (foreign_port_t * port, char *socks)
{
  char *local_sock;
  char *remote_sock;
  struct sockaddr_un sock_addr;

  // TODO: validate!
  local_sock = strtok (socks, ":");
  remote_sock = strtok (NULL, ":");

  if (yap_verbose >= LOG_EXTENDED)
    {
      log_fmt ("binding to %s\n", local_sock);
      log_fmt ("connecting to %s\n", remote_sock);
    }

  if ((port->sfd = socket (AF_UNIX, SOCK_DGRAM, 0)) < 0)
    fatal_error ("socket");

  /* bind */
  memset (&sock_addr, 0, sizeof sock_addr);
  sock_addr.sun_family = AF_UNIX;
  strcpy (sock_addr.sun_path, local_sock);
  unlink (sock_addr.sun_path);
  if (bind (port->sfd, (struct sockaddr *) &sock_addr, sizeof sock_addr))
    fatal_error ("bind");
  /* save it so we can clean it up later */
  port->socket_fname = local_sock;

  /* connect */
  port->sa_len = sizeof port->sa_un;
  memset (&port->sa_un, 0, port->sa_len);
  port->sa_un.sun_family = AF_UNIX;
  strcpy (port->sa_un.sun_path, remote_sock);

  /* We'll *try* to connect now. */
  if (connect (port->sfd, &port->sa, port->sa_len) == -1)
    {
      /* Some connect errors are okay. We'll just try again later. */
      switch (errno)
        {
        case ENOENT:
        case ECONNREFUSED:
          break;
        default:
          fatal_error ("connect");
        }
    }
}


static void
open_tunnel_udp (foreign_port_t * port, char *ports)
{
  char *local_port;
  char *remote_host;
  char *remote_port;

  int sfd;
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  int yes = 1;

  // TODO: validate data
  local_port = strtok (ports, ":");
  remote_host = strtok (NULL, ":");
  remote_port = strtok (NULL, ":");

  if (yap_verbose >= LOG_EXTENDED)
    {
      log_fmt ("binding to UDP port %s\n", local_port);
      log_fmt ("connecting to UDP %s:%s\n", remote_host, remote_port);
    }


  /* bind */

  memset (&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;
  hints.ai_protocol = 0;
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;

  // TODO: allow binding to a specific IP address
  if (getaddrinfo (NULL, local_port, &hints, &result) != 0)
    fatal_error ("getaddrinfo");

  for (rp = result; rp != NULL; rp = rp->ai_next)
    {
      sfd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
      if (sfd == -1)
        continue;

      setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
      if (bind (sfd, rp->ai_addr, rp->ai_addrlen) == 0)
        break;

      close (sfd);
    }

  if (rp == NULL)
    die ("Could not bind");

  freeaddrinfo (result);

  /* connect */

  memset (&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = 0;
  hints.ai_protocol = 0;

  if (getaddrinfo (remote_host, remote_port, &hints, &result) != 0)
    fatal_error ("getaddrinfo");

  for (rp = result; rp != NULL; rp = rp->ai_next)
    {
      if (connect (sfd, rp->ai_addr, rp->ai_addrlen) != -1)
        break;

      close (sfd);
    }

  if (rp == NULL)
    die ("Could not connect");

  freeaddrinfo (result);

  port->sfd = sfd;
}


static int
open_iou_uds ()
{
  int sfd;
  struct sockaddr_un sock_addr;

  if ((sfd = socket (AF_UNIX, SOCK_DGRAM, 0)) < 0)
    fatal_error ("socket");

  memset (&sock_addr, 0, sizeof sock_addr);
  sock_addr.sun_family = AF_UNIX;
  set_socket_filename (sock_addr.sun_path, yap_appl_id);

  unlink (sock_addr.sun_path);
  if (bind (sfd, (struct sockaddr *) &sock_addr, sizeof sock_addr))
    fatal_error ("bind");
  
  if( getuid() != geteuid() )
    if( chown(sock_addr.sun_path, getuid (), -1) )
        fatal_error ("chown");

  return sfd;
}


static int
open_iou_udp ()
{
  int sfd;
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  char local_port[6];
  int yes = 1;

  memset (&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
  hints.ai_protocol = 0;
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;

  // TODO: allow binding to a specific IP address
  snprintf (local_port, sizeof(local_port), "%u", get_iou_udp_port (yap_appl_id));
  if (getaddrinfo (NULL, local_port, &hints, &result) != 0)
    fatal_error ("getaddrinfo");

  for (rp = result; rp != NULL; rp = rp->ai_next)
    {
      sfd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
      if (sfd == -1)
        continue;

      setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
      if (bind (sfd, rp->ai_addr, rp->ai_addrlen) == 0)
        break;

      close (sfd);
    }

  if (rp == NULL)
    die ("Could not bind");

  freeaddrinfo (result);

  return sfd;
}


static iou_node_t *
make_node_table (foreign_port_t * port, int UDS_sfd, int UDP_sfd)
{
  list_node_t *it;
  int segment_size;
  iou_node_t *nodes;
  node_t *dst_node;
  iou_hdr_t iou_hdr;
  int i, j;

  /* segment size, minus us */
  segment_size = port->segment->size - 1;
  nodes = calloc (segment_size, sizeof *nodes);

  /* We can fill in the static portions of the IOU header now */
  /* SRC ID */
  iou_hdr.src_node.ids.id = yap_appl_id;
  iou_hdr.src_node.ids.subid = 0;
  iou_hdr.src_node.ids.subid_present = 0;
  /* SRC port */
  iou_hdr.src_node.port = unpack_port (port->iou_port);
  /* message type */
  iou_hdr.msg_type = IOU_MSG_TYPE_DATA;
  /* channel number */
  iou_hdr.channel = 0;

  it = port->segment->first;
  i = 0;
  do
    {
      /* Get the IOU node out of the segment chain's node */
      dst_node = (node_t *) it->data;

      /* We won't be sending packets to ourself */
      if (dst_node->ids.id == iou_hdr.src_node.ids.id
          && dst_node->ids.subid == iou_hdr.src_node.ids.subid
          && dst_node->ids.subid_present == iou_hdr.src_node.ids.subid_present
          && dst_node->port.unit == iou_hdr.src_node.port.unit
          && dst_node->port.bay == iou_hdr.src_node.port.bay)
        continue;

      /* Finish building the IOU header */
      iou_hdr.dst_node.ids = dst_node->ids;
      iou_hdr.dst_node.port = dst_node->port;
      build_iou_hdr (nodes[i].header, iou_hdr);

      if (DEBUG_LOG && yap_verbose >= LOG_CRAZY)
        {
          if (dst_node->ids.subid_present)
            {
              log_fmt ("header for IOU node %d:%d/%d/%d", dst_node->ids.id,
                       dst_node->ids.subid, dst_node->port.bay,
                       dst_node->port.unit);
            }
          else
            {
              log_fmt ("header for IOU node %d:%d/%d", dst_node->ids.id,
                       dst_node->port.bay, dst_node->port.unit);
            }
          fprintf(stderr,": 0x");
          for (j = 0; j < IOU_HDR_SIZE; j++)
            fprintf(stderr, "%.2X ", nodes[i].header[j]);
          fprintf(stderr, "\n");
        }

      if (yap_verbose >= LOG_NOISY)
        {
          if (dst_node->ids.subid_present)
            {
              log_fmt ("communicating with %d:%d/%d/%d", dst_node->ids.id,
                       dst_node->ids.subid, dst_node->port.bay,
                       dst_node->port.unit);
            }
          else
            {
              log_fmt ("communicating with %d:%d/%d", dst_node->ids.id,
                       dst_node->port.bay, dst_node->port.unit);
            }
        }

      if (dst_node->addr.s_addr != INADDR_NONE)
        {
          nodes[i].sfd = UDP_sfd;

          memset (&nodes[i].sa_in, 0, sizeof nodes[i].sa_in);
          nodes[i].sa_in.sin_family = AF_INET;
          nodes[i].sa_in.sin_port =
            htons (get_iou_udp_port (dst_node->ids.id));
          nodes[i].sa_in.sin_addr = dst_node->addr;
          nodes[i].sa_len = sizeof nodes[i].sa_in;

          if (yap_verbose >= LOG_NOISY)
            fprintf(stderr, " via UDP: %s:%d\n", inet_ntoa (dst_node->addr),
                    get_iou_udp_port (dst_node->ids.id));
        }
      else
        {
          nodes[i].sfd = UDS_sfd;

          memset (&nodes[i].sa_un, 0, sizeof nodes[i].sa_un);
          nodes[i].sa_un.sun_family = AF_UNIX;
          set_socket_filename (nodes[i].sa_un.sun_path, dst_node->ids.id);
          nodes[i].sa_len = sizeof nodes[i].sa_un;

          if (yap_verbose >= LOG_NOISY)
            fprintf(stderr, " via UDS: %s\n", nodes[i].sa_un.sun_path);
        }

      i++;
    }
  while ((it = it->next) != NULL);

  return nodes;
}


// TODO: we need to break this up
static void
create_foreign_threads (pthread_attr_t * thread_attrs,
                        int UDS_sfd, int UDP_sfd)
{
  char *value = NULL;
  char key[MAX_KEY_SIZE];
  char port_key[6];
  int i, j;
  int s;
  port_t port;
  int pcap_no_header;
  int pcap_overwrite;
  char *pcap_protocol;

  for (i = 0; i < MAX_PORTS; i++)
    {
      port_table[i].iou_port = i;
      port_table[i].nodes = NULL;
      port_table[i].sfd = NO_FD;

      /* packet capture */
      port_table[i].span_sfd = NO_FD;
      port_table[i].pcap_fifo = NULL;
      port_table[i].pcap_fd = NO_FD;

      port = unpack_port (i);
      snprintf (port_key, sizeof(port_key), "%d/%d", port.bay, port.unit);
      snprintf (key, sizeof(key), "%d:%s", yap_appl_id, port_key);

      /* Don't bother if the section doesn't even exist */
      if (!ini_find (key))
          continue;

      if (port_table[i].segment == NULL)
        {
          log_fmt ("No segment using %s. Not starting listener.\n", key);
          continue;
        }

      log_msg ("--------------");
      log_fmt ("Configuring %s...\n", key);

      if (ini_getstr_port (&value, port_key, "eth_dev"))
        {
          open_eth_dev (&port_table[i], value);
        }
      else if (ini_getstr_port (&value, port_key, "tap_dev"))
        {
          open_tap_dev (&port_table[i], value);
        }
      else if (ini_getstr_port (&value, port_key, "tunnel_uds"))
        {
          open_tunnel_uds (&port_table[i], value);
        }
      else if (ini_getstr_port (&value, port_key, "tunnel_udp"))
        {
          open_tunnel_udp (&port_table[i], value);
        }
      else
        {
          log_msg ("no foreign interface specified");
          continue;
        }

      if (ini_getstr_port (&value, port_key, "span_dev"))
        {
          open_span_dev (&port_table[i], value);
        }

      pcap_no_header = ini_getbool_port_def (port_key, "pcap_no_header", 0);
      pcap_overwrite = ini_getbool_port_def (port_key, "pcap_overwrite", 0);
      port_table[i].pcap_linktype =
          ini_getint_port_def (port_key, "pcap_linktype", LINKTYPE_ETHERNET);

      pcap_protocol = ini_getstr_port_def (port_key, "pcap_protocol", "");
      /* We want to be case-insensitive */
      for (j = 0; pcap_protocol[j]; j++)
        {
          pcap_protocol[j] = toupper(pcap_protocol[j]);
        }
      if (strcmp(pcap_protocol, "PPP") == 0)
        {
          port_table[i].pcap_linktype = LINKTYPE_PPP_HDLC;
        }
      else if (strcmp(pcap_protocol, "HDLC") == 0 ||
               strcmp(pcap_protocol, "CHDLC") == 0)
        {
          port_table[i].pcap_linktype = LINKTYPE_C_HDLC;
        }
      else if (strcmp(pcap_protocol, "ETHERNET") == 0 ||
               strcmp(pcap_protocol, "ETHER") == 0 ||
               strcmp(pcap_protocol, "ETH") == 0)
        {
          port_table[i].pcap_linktype =  LINKTYPE_ETHERNET;
        }
      else if (strcmp(pcap_protocol, "FRELAY") == 0 ||
               strcmp(pcap_protocol, "FR") == 0 ||
               strcmp(pcap_protocol, "FRAMERELAY") == 0)
        {
          port_table[i].pcap_linktype = LINKTYPE_FRELAY;
        }
      else if (pcap_protocol[0] != '\0')
        {
          log_fmt ("Unknown pcap protocol: %s\n", pcap_protocol);
        }

      port_table[i].pcap_caplen =
          ini_getint_port_def (port_key, "pcap_caplen", MAX_MTU);

      if (ini_getstr_port (&value, port_key, "pcap_file"))
        {
          open_pcap_file (&port_table[i], value,
                          pcap_no_header, pcap_overwrite);
        }
      else if (ini_getstr_port (&value, port_key, "pcap_pipe"))
        {
          /* Only writes up to PIPE_BUF bytes are atomic! (4K in Linux) */
          if (port_table[i].pcap_caplen > PIPE_BUF)
            port_table[i].pcap_caplen = PIPE_BUF;
          open_pcap_pipe (&port_table[i], value, pcap_no_header);
        }

      port_table[i].nodes = make_node_table (&port_table[i],
                                             UDS_sfd, UDP_sfd);

      log_msg ("starting foreign listener");
      s = pthread_create (&port_table[i].thread_id, thread_attrs,
                          &foreign_listener, &port_table[i]);
      if (s != 0)
        fatal_error_en (s, "pthread_create");
    }
}


void
free_port_table (foreign_port_t *port_table)
{
  int i;

  for (i = 0; i < MAX_PORTS; i++)
    {
      /* Delete segment chains */
      if (port_table[i].segment != NULL)
        {
          /* The same chain may be shared with multiple ports! */
          if (port_table[i].segment->ref_cnt == 1)
            delete_chain (port_table[i].segment);
          else
            port_table[i].segment->ref_cnt--;
        }

      /* Cancel threads, close file descriptors, etc. */
      if (port_table[i].sfd != NO_FD)
        {
          pthread_cancel (port_table[i].thread_id);
          close (port_table[i].sfd);
          if (port_table[i].socket_fname)
            unlink (port_table[i].socket_fname);
          if (port_table[i].span_sfd != NO_FD)
            close (port_table[i].span_sfd);
          if (port_table[i].pcap_fifo)
            unlink (port_table[i].pcap_fifo);
          if (port_table[i].pcap_fd != NO_FD)
            close (port_table[i].pcap_fd);
        }

      /* Free port's node table */
      if (port_table[i].nodes != NULL)
        free (port_table[i].nodes);
    }

  free (port_table);
}


static void
print_usage (void)
{
  printf("Usage: %s [OPTION]... ID\n"
         "       %s [OPTION]... DEV_OPT ID:BAY/UNIT\n"
         "\n"
         "Options:\n"
         "  -h                   print this message and exit\n"
         "  -q                   suppress most output\n"
         "  -v|v|v               increase output\n"
         "  -d                   run in background\n"
         "  -c                   do not read configuration file\n"
         "  -f FILE              specify configuration file\n"
         "  -n FILE              specify NETMAP file\n"
         "  -V                   print version and exit\n"
         "\n"
         "Device options:\n"
         "  -e ETH_DEV           connect to Ethernet device\n"
         "  -t TAP_DEV           connect to TAP device\n"
         "  -u LPORT:ADDR:RPORT  create UDP tunnel\n"
         "  -s LFILE:RFILE       connect via Unix domain socket\n",
         program_invocation_short_name,
         program_invocation_short_name);
}


static void
print_for_help (void)
{
  fprintf(stderr, "Use '%s -h' for help.\n",
          program_invocation_short_name);
}


int
main (int argc, char **argv)
{
  sigset_t sigset;
  int sig;

  int s;
  pthread_t UDS_thread_id, UDP_thread_id;

  char opt;
  char *config_ini = CONFIG_FILE;
  char *netmap_file = NULL;

  char sock_name[UNIX_PATH_MAX];
  char sock_dir[UNIX_PATH_MAX];
  int sock_lock;
  pid_t lock_pid;

  int UDS_sfd;
  int UDP_sfd;

  pthread_attr_t thread_attrs;

  unsigned int cmdline_netmap = 0;
  char *cmdline_dev_type = NULL;
  char *cmdline_dev = NULL;
  char key[MAX_KEY_SIZE];
  char *cmdline_node = NULL;

#define NUM_NONOPT 1
  while ((opt = getopt (argc, argv, "hvdqcVf:n:e:t:u:s:")) != -1)
    {
      switch (opt)
        {
        case 'h':
          print_usage ();
          exit (EXIT_SUCCESS);
        case 'q':
          yap_verbose = LOG_QUIET;
          break;
        case 'v':
          yap_verbose++;
          break;
        case 'd':
          /* Immediately put us into the background
           * (good enough for now)
           */
          daemon(1, 1);  /* don't change dir, don't redirect stdio */
          break;
        case 'c':
          config_ini = "/dev/null";
          break;
        case 'V':
          printf("%s version %s\n", NAME, VERSION);
          exit (EXIT_SUCCESS);
        case 'f':
          config_ini = optarg;
          break;
        case 'n':
          netmap_file = optarg;
          cmdline_netmap = 1;
          break;
        case 'e':
          cmdline_dev_type = "eth_dev";
          cmdline_dev = optarg;
          break;
        case 't':
          cmdline_dev_type = "tap_dev";
          cmdline_dev = optarg;
          break;
        case 'u':
          cmdline_dev_type = "tunnel_udp";
          cmdline_dev = optarg;
          break;
        case 's':
          cmdline_dev_type = "tunnel_uds";
          cmdline_dev = optarg;
          break;
        default:               /* '?' */
          /* getopt prints an error message for us */
          print_for_help ();
          exit (EXIT_FAILURE);
        }
    }

  /* check non-option args */
  if (optind + NUM_NONOPT != argc)
    {
      fprintf(stderr, "%s: invalid args\n",
              program_invocation_name);
      print_for_help ();
      exit (EXIT_FAILURE);
    }

  if (cmdline_dev_type == NULL)
    {
      yap_appl_id = atoi (argv[optind]);
    }
  else
    {
      cmdline_node = strdup (argv[optind]);
      yap_appl_id = atoi (strtok (argv[optind], ":"));
    }
  optind++;

  /* The program version can be nice to know */
  if (DEBUG_LOG || yap_verbose >= LOG_EXTENDED)
    log_fmt ("%s %s starting\n", NAME, VERSION);

  sigemptyset (&sigset);
  sigaddset (&sigset, SIGHUP);
  sigaddset (&sigset, SIGTERM);
  sigaddset (&sigset, SIGINT);
  pthread_sigmask (SIG_BLOCK, &sigset, NULL);

  set_socket_directory (sock_dir);
  mkdir (sock_dir, S_IRUSR | S_IWUSR | S_IXUSR);

  set_socket_filename (sock_name, yap_appl_id);
  if ((sock_lock = lock_socket (sock_name)) < 0)
    {
      if ((lock_pid = get_socket_lock (sock_name)) < 0)
        die_fmt ("Could not get lock on %s\n", sock_name);
      die_fmt ("PID %u already has a lock on ID %u\n",
               lock_pid, yap_appl_id);
    }

  /* thread creation attributes */
  s = pthread_attr_init (&thread_attrs);
  if (s != 0)
    fatal_error_en (s, "pthread_attr_init");
  s = pthread_attr_setdetachstate (&thread_attrs, PTHREAD_CREATE_DETACHED);
  if (s != 0)
    fatal_error_en (s, "pthread_attr_setdetachstate");

  for (;;)
    {
      /* INI config */
      if ((yap_config = iniparser_load (config_ini)) == NULL)
        die ("cannot load configuration file");

      if (cmdline_dev_type != NULL)
        {
          /* Need to create the section first */
          iniparser_set (yap_config, cmdline_node, NULL);

          /* Now create the key=value pair */
          snprintf (key, sizeof(key), "%s:%s", cmdline_node, cmdline_dev_type);
          iniparser_set (yap_config, key, cmdline_dev);

          free (cmdline_node);
        }

      /* port table init */
      port_table = calloc (MAX_PORTS, sizeof *port_table);
      if (port_table == NULL)
        fatal_error ("Couldn't calloc port table!");

      /* NETMAP */
      // TODO: add support for loading ~/.NETMAP and NETIO_NETMAP env var
      if (!cmdline_netmap)
        netmap_file = ini_getstr_id_def ("netmap", NETMAP_FILE);

      log_msg("Parsing NETMAP...");
      if (!parse_netmap (netmap_file)
          && ini_getbool_id_def ("strict_mode", DEFAULT_STRICT_MODE))
        die ("exiting because of NETMAP errors (strict mode enabled)");

      /* Open the iou sockets */
      UDS_sfd = open_iou_uds ();
      UDP_sfd = open_iou_udp ();

      /* Create foreign listeners */
      create_foreign_threads (&thread_attrs, UDS_sfd, UDP_sfd);
      log_msg ("--------------");
      /* Create IOU listeners */
      log_msg ("Starting IOU UDS listener");
      s = pthread_create (&UDS_thread_id, &thread_attrs,
                          &iou_listener, &UDS_sfd);
      if (s != 0)
        fatal_error_en (s, "Couldn't create IOU UDS listener thread!");
      log_msg ("Starting IOU UDP listener");
      s = pthread_create (&UDP_thread_id, &thread_attrs,
                          &iou_listener, &UDP_sfd);
      if (s != 0)
        fatal_error_en (s, "Couldn't create IOU UDP listener thread!");

      log_msg ("Main thread going to sleep");

      /* Time to go to sleep. Wait for a signal. */
      sigwait (&sigset, &sig);
      log_fmt ("Received signal %d\n", sig);
      log_msg ("Stopping listeners and cleaning up");

      /* Cancel IOU threads and close their file descriptors */
      /* UDS */
      pthread_cancel (UDS_thread_id);
      close (UDS_sfd);
      unlink (sock_name);
      /* UDP */
      pthread_cancel (UDP_thread_id);
      close (UDP_sfd);

      free_port_table (port_table);
      iniparser_freedict (yap_config);

      /* Should we exit? */
      if (sig == SIGTERM || sig == SIGINT)
        break;

      log_msg ("Reloading configuration because of SIGHUP");
    }

  log_msg ("Exiting");

  pthread_attr_destroy (&thread_attrs);

  s = unlock_socket (sock_lock, sock_name);
  if (s == -1)
    log_error ("Failed to unlock");

  return EXIT_SUCCESS;
}


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
