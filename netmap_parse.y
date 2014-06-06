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

%{
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "netmap.h"
#include "iouyap.h"


extern int yylineno;
extern int yylex();

void yyerror(const char *msg);
unsigned int param_error = 0;
unsigned int errors_found = 0;


#define RANGE_CHECK(item, value, item_min, item_max)                    \
    do {                                                                \
        if (value < item_min || value > item_max) {                     \
            log_fmt("invalid %s value (%d) (%d <= %s <= %d)\n",         \
                    item, value, item_min, item, item_max);             \
            param_error = 1;                                            \
            errors_found++;                                             \
        }                                                               \
    } while (0)

%}

// token types
%union {
    int ival;
    char *sval;
    char pval[64];
}
%token  <ival>  INT
%token  <sval>  ADDRESS
%token          ENDSEG
%token          ENDNODE

%type   <pval>  params
%type   <pval>  host

%destructor { free($$); } <sval>


%%

netmap
    : netmap segment_line
    | segment_line
    ;
segment_line
    : segment ENDSEG            {   end_segment(); }
    ;
segment
    : segment node
    | node
    ;
node
    : INT params host ENDNODE   {
                                    RANGE_CHECK("ID", $1, ID_MIN, ID_MAX);
                                    iou_node_tmp->ids.id = $1;

                                    if (param_error) {
                                        log_fmt("^^ NETMAP line %d: ignoring node %d%s%s\n",
                                                yylineno, $1, $2, $3);
                                        param_error = 0;
                                        memset(iou_node_tmp, 0, sizeof(*iou_node_tmp));
                                    } else {
                                        add_node();
                                    }
                                }
    | INT error ENDNODE         {   log_fmt("^^ NETMAP line %d: ignoring node id %d\n",
                                            yylineno, $1); }
    ;
params
    : ':' INT                   {
                                    sprintf($$, ":%d", $2);
                                    RANGE_CHECK("PORT", $2, PORT_MIN, PORT_MAX);
                                    iou_node_tmp->port = unpack_port ($2);
                                }
    | ':' INT '/' INT           {
                                    sprintf($$, ":%d/%d", $2, $4);
                                    RANGE_CHECK("BAY", $2, BAY_MIN, BAY_MAX);
                                    RANGE_CHECK("UNIT", $4, UNIT_MIN, UNIT_MAX);
                                    iou_node_tmp->port.bay = $2;
                                    iou_node_tmp->port.unit = $4;
                                }
    | ':' INT '/' INT '/' INT   {
                                    sprintf($$, ":%d/%d/%d", $2, $4, $6);
                                    RANGE_CHECK("SUBID", $2, SUBID_MIN, SUBID_MAX);
                                    RANGE_CHECK("BAY", $4, BAY_MIN, BAY_MAX);
                                    RANGE_CHECK("UNIT", $6, UNIT_MIN, UNIT_MAX);
                                    iou_node_tmp->ids.subid_present = 1;
                                    iou_node_tmp->ids.subid = $2;
                                    iou_node_tmp->port.bay = $4;
                                    iou_node_tmp->port.unit = $6;
                                }
    ;
host
    : /* empty */               {
                                    iou_node_tmp->addr.s_addr = INADDR_NONE;
                                    $$[0] = '\0';
                                }
    | '@' ADDRESS               {
                                    struct hostent *host;

                                    sprintf($$, "@%s", $2);
                                    host = gethostbyname ($2);
                                    if (host == NULL)
                                      {
                                        log_fmt ("gethostbyname(%s) failed: ", $2);
                                        herror ("");
                                        param_error = 1;
                                        errors_found++;
                                      }
                                    else
                                      {
                                        iou_node_tmp->addr = *(struct in_addr *)host->h_addr_list[0];
                                        if (yap_verbose >= LOG_NOISY)
                                          log_fmt ("gethostbyname(%s) = %s = %s\n", $2, host->h_name,
                                                       inet_ntoa (iou_node_tmp->addr));
                                      }
                                    free($2);
                                }
    ;


%%

/* for syntax errors */
void yyerror(const char *msg) {
    log_msg(msg);
    errors_found++;
}
