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

#include <iniparser.h>

#include "config.h"


extern short yap_appl_id;
extern dictionary *yap_config;


#define KEY_DEF(key, param) \
  sprintf(key, "%s:%s", DEFAULT_SECTION, param)
#define KEY_ID(key, param)  \
  sprintf(key, "%d:%s", yap_appl_id, param)
#define KEY_PORT(key, port, param) \
  sprintf(key, "%d:%s:%s", yap_appl_id, port, param)


int
ini_find (char *key)
{
  return iniparser_find_entry (yap_config, key);
}


int
ini_find_default (char *param)
{
  char key[MAX_KEY_SIZE];

  KEY_DEF (key, param);
  return ini_find (key);
}


int
ini_find_id (char *param)
{
  char key[MAX_KEY_SIZE];

  KEY_ID (key, param);
  return ini_find (key);
}


int
ini_find_port (char *port, char *param)
{
  char key[MAX_KEY_SIZE];

  KEY_PORT (key, port, param);
  return ini_find (key);
}

// string

int
ini_getstr (char **value, char *key)
{
  if (!ini_find (key))
    return 0;
  *value = iniparser_getstring (yap_config, key, NULL);
  return 1;
}


int
ini_getstr_default (char **value, char *param)
{
  char key[MAX_KEY_SIZE];

  KEY_DEF (key, param);
  if (ini_getstr (value, key))
    return 1;
  return 0;
}


int
ini_getstr_id (char **value, char *param)
{
  char key[MAX_KEY_SIZE];

  KEY_ID (key, param);
  if (ini_getstr (value, key))
    return 1;
  return ini_getstr_default (value, param);
}


int
ini_getstr_port (char **value, char *port, char *param)
{
  char key[MAX_KEY_SIZE];

  KEY_PORT (key, port, param);
  if (ini_getstr (value, key))
    return 1;
  return ini_getstr_id (value, param);
}


char *
ini_getstr_default_def (char *param, char *def)
{
  char *value = NULL;

  if (!ini_getstr_default (&value, param))
    return def;
  return value;
}


char *
ini_getstr_id_def (char *param, char *def)
{
  char *value = NULL;

  if (!ini_getstr_id (&value, param))
    return def;
  return value;
}


char *
ini_getstr_port_def (char *port, char *param, char *def)
{
  char *value = NULL;

  if (!ini_getstr_port (&value, port, param))
    return def;
  return value;
}

// integer

int
ini_getint (int *value, char *key)
{
  if (!ini_find (key))
    return 0;
  *value = iniparser_getint (yap_config, key, 0);
  return 1;
}


int
ini_getint_default (int *value, char *param)
{
  char key[MAX_KEY_SIZE];

  KEY_DEF (key, param);
  if (ini_getint (value, key))
    return 1;
  return 0;
}


int
ini_getint_id (int *value, char *param)
{
  char key[MAX_KEY_SIZE];

  KEY_ID (key, param);
  if (ini_getint (value, key))
    return 1;
  return ini_getint_default (value, param);
}


int
ini_getint_port (int *value, char *port, char *param)
{
  char key[MAX_KEY_SIZE];

  KEY_PORT (key, port, param);
  if (ini_getint (value, key))
    return 1;
  return ini_getint_id (value, param);
}


int
ini_getint_default_def (char *param, int def)
{
  int value;

  if (!ini_getint_default (&value, param))
    return def;
  return value;
}


int
ini_getint_id_def (char *param, int def)
{
  int value;

  if (!ini_getint_id (&value, param))
    return def;
  return value;
}


int
ini_getint_port_def (char *port, char *param, int def)
{
  int value;

  if (!ini_getint_port (&value, port, param))
    return def;
  return value;
}

// boolean

int
ini_getbool (int *value, char *key)
{
  if (!ini_find (key))
    return 0;
  *value = iniparser_getboolean (yap_config, key, -1);
  return 1;
}


int
ini_getbool_default (int *value, char *param)
{
  char key[MAX_KEY_SIZE];

  KEY_DEF (key, param);
  if (ini_getbool (value, key))
    return 1;
  return 0;
}


int
ini_getbool_id (int *value, char *param)
{
  char key[MAX_KEY_SIZE];

  KEY_ID (key, param);
  if (ini_getbool (value, key))
    return 1;
  return ini_getbool_default (value, param);
}


int
ini_getbool_port (int *value, char *port, char *param)
{
  char key[MAX_KEY_SIZE];

  KEY_PORT (key, port, param);
  if (ini_getbool (value, key))
    return 1;
  return ini_getbool_id (value, param);
}


int
ini_getbool_default_def (char *param, int def)
{
  int value;

  if (!ini_getbool_default (&value, param))
    return def;
  return value;
}


int
ini_getbool_id_def (char *param, int def)
{
  int value;

  if (!ini_getbool_id (&value, param))
    return def;
  return value;
}


int
ini_getbool_port_def (char *port, char *param, int def)
{
  int value;

  if (!ini_getbool_port (&value, port, param))
    return def;
  return value;
}

// double

int
ini_getdouble (double *value, char *key)
{
  if (!ini_find (key))
    return 0;
  *value = iniparser_getdouble (yap_config, key, -1.0);
  return 1;
}


int
ini_getdouble_default (double *value, char *param)
{
  char key[MAX_KEY_SIZE];

  KEY_DEF (key, param);
  if (ini_getdouble (value, key))
    return 1;
  return 0;
}


int
ini_getdouble_id (double *value, char *param)
{
  char key[MAX_KEY_SIZE];

  KEY_ID (key, param);
  if (ini_getdouble (value, key))
    return 1;
  return ini_getdouble_default (value, param);
}


int
ini_getdouble_port (double *value, char *port, char *param)
{
  char key[MAX_KEY_SIZE];

  KEY_PORT (key, port, param);
  if (ini_getdouble (value, key))
    return 1;
  return ini_getdouble_id (value, param);
}


double
ini_getdouble_default_def (char *param, double def)
{
  double value;

  if (!ini_getdouble_default (&value, param))
    return def;
  return value;
}


double
ini_getdouble_id_def (char *param, double def)
{
  double value;

  if (!ini_getdouble_id (&value, param))
    return def;
  return value;
}


double
ini_getdouble_port_def (char *port, char *param, double def)
{
  double value;

  if (!ini_getdouble_port (&value, port, param))
    return def;
  return value;
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
