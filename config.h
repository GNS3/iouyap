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

#ifndef CONFIG_H_
#define CONFIG_H_


#define MAX_KEY_SIZE 256
#define DEFAULT_SECTION "default"


int ini_find (char *key);
int ini_find_default (char *param);
int ini_find_id (char *param);
int ini_find_port (char *port, char *param);

// string
int ini_getstr (char **value, char *key);
int ini_getstr_default (char **value, char *param);
int ini_getstr_id (char **value, char *param);
int ini_getstr_port (char **value, char *port, char *param);
char *ini_getstr_default_def (char *param, char *def);
char *ini_getstr_id_def (char *param, char *def);
char *ini_getstr_port_def (char *port, char *param, char *def);
// integer
int ini_getint (int *value, char *key);
int ini_getint_default (int *value, char *param);
int ini_getint_id (int *value, char *param);
int ini_getint_port (int *value, char *port, char *param);
int ini_getint_default_def (char *param, int def);
int ini_getint_id_def (char *param, int def);
int ini_getint_port_def (char *port, char *param, int def);
// boolean
int ini_getbool (int *value, char *key);
int ini_getbool_default (int *value, char *param);
int ini_getbool_id (int *value, char *param);
int ini_getbool_port (int *value, char *port, char *param);
int ini_getbool_default_def (char *param, int def);
int ini_getbool_id_def (char *param, int def);
int ini_getbool_port_def (char *port, char *param, int def);
// double
int ini_getdouble (double *value, char *key);
int ini_getdouble_default (double *value, char *param);
int ini_getdouble_id (double *value, char *param);
int ini_getdouble_port (double *value, char *port, char *param);
double ini_getdouble_default_def (char *param, double def);
double ini_getdouble_id_def (char *param, double def);
double ini_getdouble_port_def (char *port, char *param, double def);


#endif /* CONFIG_H_ */



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
