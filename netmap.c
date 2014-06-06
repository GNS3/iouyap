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

/* Special thanks to Julienne Walker for making Eternally Confuzzled,
 * http://eternallyconfuzzled.com . It is from here where the hash table
 * and linked list functions were stolen.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "iouyap.h"
#include "netmap.h"
#include "y.tab.h"


typedef struct
{
  appl_id_t ids;
  port_t port;
} ht_key_t;

typedef struct
{
  list_head_t **table;
  size_t size;
  size_t capacity;
} ht_hash_table_t;

extern int yylex_destroy ();
extern int h_errno;
extern short errors_found;

node_t *iou_node_tmp = NULL;
ht_hash_table_t *hash_table = NULL;
list_head_t *segment_chain = NULL;
int seg_counter = 0;


/* One-at-a-time hash, by Bob Jenkins
 * see http://www.burtleburtle.net/bob/hash/doobs.html
 */
static unsigned int
oat_hash (void *key, unsigned int len)
{
  unsigned char *p = key;
  unsigned int h = 0;
  unsigned int i;

  for (i = 0; i < len; i++)
    {
      h += p[i];
      h += (h << 10);
      h ^= (h >> 6);
    }

  h += (h << 3);
  h ^= (h >> 11);
  h += (h << 15);

  return h;
}


static node_t *
new_iou_node (void)
{
  node_t *n;

  n = malloc (sizeof *n);
  if (n == NULL)
    fatal_error ("cannot allocate memory for IOU node");
  memset (n, 0, sizeof *n);
  return n;
}


void
delete_chain (list_head_t *chain)
{
  list_node_t *save, *it;

  it = chain->first;
  for (; it != NULL; it = save)
    {
      save = it->next;
      free (it->data);
      free (it);
    }
  free (chain);
}


static list_node_t *
list_new_node (void *data, list_node_t * next)
{
  list_node_t *node;

  node = malloc (sizeof *node);
  if (node == NULL)
    fatal_error ("cannot allocate memory for list node");

  node->data = data;
  node->next = next;

  return node;
}


static list_head_t *
list_new_chain (void)
{
  list_head_t *chain;

  chain = malloc (sizeof *chain);
  if (chain == NULL)
    fatal_error ("malloc");

  chain->first = NULL;
  chain->size = 0;
  chain->ref_cnt = 0;

  return chain;
}


static void
pt_insert_node (list_head_t * head, void *data)
{
  list_node_t *new_item;

  new_item = list_new_node (data, NULL);
  new_item->next = head->first;
  head->first = new_item;
  head->size++;
}


static ht_hash_table_t *
ht_create_table (size_t size)
{
  ht_hash_table_t *htab;
  size_t i;

  htab = malloc (sizeof *htab);
  if (htab == NULL)
    fatal_error ("cannot allocate memory for hash table");

  htab->table = calloc (size, sizeof *htab->table);
  if (htab->table == NULL)
    {
      free (htab);
      fatal_error ("cannot allocate memory for hash table");
    }

  /* Empty chains have no head */
  for (i = size; i--;)
    htab->table[i] = NULL;

  htab->size = 0;
  htab->capacity = size;

  return htab;
}


static void
ht_delete_table (ht_hash_table_t * htab)
{
  size_t i;

  /* Release each chain individually */
  for (i = htab->capacity; i--;)
    {
      if (htab->table[i] == NULL)
        continue;

      delete_chain (htab->table[i]);
    }

  /* Release the hash table */
  free (htab->table);
  free (htab);
}


static int
ht_find_node (ht_hash_table_t * htab, void *key)
{
  unsigned int h;

  h = oat_hash (key, sizeof (ht_key_t)) % htab->capacity;

  /* Search the chain only if it exists */
  if (htab->table[h] != NULL)
    {
      list_node_t *it = htab->table[h]->first;

      for (; it != NULL; it = it->next)
        {
          if (memcmp (key, it->data, sizeof (ht_key_t)) == 0)
            return 1;
        }
    }
  return 0;
}


static int
ht_insert_node (ht_hash_table_t * htab, void *key)
{
  unsigned int h;
  list_node_t *new_item;

  h = oat_hash (key, sizeof (ht_key_t)) % htab->capacity;

  /* Disallow duplicate keys */
  if (ht_find_node (htab, key))
    return 0;

  if (htab->table[h] == NULL)
    htab->table[h] = list_new_chain ();

  /* Insert at the front of the chain */
  new_item = list_new_node (key, NULL);
  new_item->next = htab->table[h]->first;
  htab->table[h]->first = new_item;

  htab->table[h]->size++;
  htab->size++;

  return 1;
}


void
end_segment (void)
{
  list_node_t *it;
  node_t *node;

  if (yap_verbose >= LOG_NOISY)
    {
      log_fmt ("segment %d:", seg_counter);
      it = segment_chain->first;
      do
        {
          node = (node_t *)it->data;

          if (node->ids.subid_present)
            {
              fprintf (stderr, "  %d:%d/%d/%d", node->ids.id,
                       node->ids.subid, node->port.bay, node->port.unit);
            }
          else
            {
              fprintf (stderr, "  %d:%d/%d", node->ids.id,
                       node->port.bay, node->port.unit);
            }
          if (node->addr.s_addr != INADDR_NONE)
              fprintf (stderr, "@%s", inet_ntoa (node->addr));
        } while ((it = it->next) != NULL);
      fprintf (stderr, "\n");
    }

  /* We delete segment chains not involving us */
  if (segment_chain->ref_cnt == 0)
    {
      delete_chain (segment_chain);
      if (yap_verbose >= LOG_CRAZY)
        log_fmt ("deleted unused segment %d\n", seg_counter);
    }

  seg_counter++;
  segment_chain = list_new_chain ();
}


int
add_node (void)
{
  ht_key_t *key;
  int port;

  /* Create a key to use for hashing */
  key = malloc (sizeof *key);
  if (key == NULL)
    fatal_error ("malloc");
  memset (key, 0, sizeof (*key));
  key->ids = iou_node_tmp->ids;
  key->port = iou_node_tmp->port;

  /* Try to add the key to the hash table. Avoid duplicates. */
  if (!ht_insert_node (hash_table, key))
    {
      free (key);
      return 0;
    }

  if (DEBUG_LOG && yap_verbose >= LOG_CRAZY)
    {
      if (iou_node_tmp->ids.subid_present)
        {
          log_fmt ("addind node %d:%d/%d/%d", iou_node_tmp->ids.id,
                   iou_node_tmp->ids.subid, iou_node_tmp->port.bay,
                   iou_node_tmp->port.unit);
        }
      else
        {
          log_fmt ("addind node %d:%d/%d", iou_node_tmp->ids.id,
                   iou_node_tmp->port.bay, iou_node_tmp->port.unit);
        }
      if (iou_node_tmp->addr.s_addr != INADDR_NONE)
        fprintf (stderr, "@%s", inet_ntoa (iou_node_tmp->addr));
      fprintf (stderr, " to segment %d\n", seg_counter);
    }

  pt_insert_node (segment_chain, iou_node_tmp);

  /* Is this IOU node for us? */
  if (iou_node_tmp->ids.id == yap_appl_id
      && iou_node_tmp->ids.subid_present == 0)
    {
      /* Save a pointer to the chain we're currently making */
      segment_chain->ref_cnt++;
      port = pack_port (iou_node_tmp->port);
      port_table[port].segment = segment_chain;
    }

  iou_node_tmp = new_iou_node ();

  return 1;
}


static void
dump_port_table (void)
{
  size_t i;
  list_node_t *it;
  node_t *node;
  port_t our_port;

  for (i=0; i < MAX_PORTS; i++)
    {
      if (port_table[i].segment == NULL)
        continue;

      our_port = unpack_port (i);
      log_fmt ("%d:%d/%d talks to %d other node(s):\n", yap_appl_id,
               our_port.bay, our_port.unit,
               (port_table[i].segment->size - 1));

      it = port_table[i].segment->first;
      do
        {
          node = (node_t *)it->data;

          if (node->ids.id == yap_appl_id
              && node->ids.subid_present == 0
              && pack_port (node->port) == i)
            continue;

          if (node->ids.subid_present)
            {
              log_fmt ("\t  %d:%d/%d/%d", node->ids.id, node->ids.subid,
                       node->port.bay, node->port.unit);
            }
          else
            {
              log_fmt ("\t  %d:%d/%d", node->ids.id,
                       node->port.bay, node->port.unit);
            }
          if (node->addr.s_addr != INADDR_NONE)
              fprintf(stderr, "@%s", inet_ntoa (node->addr));
          fprintf(stderr, "\n");

        } while ((it = it->next) != NULL);
    }
}


int
parse_netmap (char *file)
{
  if (!(yyin = fopen (file, "r")))
    {
      log_fmt ("Unable to open NETMAP file: %s\n", file);
      fatal_error (file);
    }

  hash_table = ht_create_table (HT_SIZE);
  segment_chain = list_new_chain ();
  iou_node_tmp = new_iou_node ();
  seg_counter = 0;
  errors_found = 0;

  /* Parse the NETMAP file */
  yyparse ();

  fclose (yyin);
  free (iou_node_tmp);
  free (segment_chain);
  yylex_destroy ();
  ht_delete_table (hash_table);

  if (yap_verbose >= LOG_BASIC)
    {
      dump_port_table ();
      log_fmt ("%d NETMAP errors\n", errors_found);
    }

  return (errors_found == 0);
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
