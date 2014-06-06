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
#include <stdio.h>

#include "iouyap.h"

#include "y.tab.h"

int comment_line = -1;
unsigned int got_node = 0;

%}

%option noyywrap nodefault yylineno noinput nounput
%x COMMENT
%x NODE
%x JUNK

INT         [[:digit:]]+
ADDRESS     [[:alnum:].-]+

%%

[ \t]+                  /* Ignore whitespace except for newline *if* we have something good */
\n                      { if (got_node) {got_node = 0; return ENDSEG;} }

{INT}:{INT}             { BEGIN NODE; yyless(0); }
<NODE>{INT}             { yylval.ival = atoi(yytext); return INT; }
<NODE>{ADDRESS}         { yylval.sval = strdup(yytext); return ADDRESS; }
<NODE>[:/@]             { return yytext[0]; }
<NODE>"/*"|.|\n         { BEGIN INITIAL; yyless(0); got_node = 1; return ENDNODE; }

    /* C-style comments (like this) are allowed in NETMAP */
"/*"                    { BEGIN COMMENT; comment_line = yylineno; }
<COMMENT>"*/"           { BEGIN INITIAL; }
<COMMENT>([^*/]|\n)+|.  /* match anything but *'s and /'s and ignore it */
<COMMENT>"/*"           { log_fmt("NETMAP line %d: nested comment\n", yylineno); }
<COMMENT><<EOF>>        { log_fmt("NETMAP line %d: unterminated comment\n", comment_line); yyterminate(); }
"*/"                    { log_fmt("NETMAP line %d: terminator found outside of comment\n", yylineno); }

.                       { BEGIN JUNK; yyless(0); }
<JUNK>"/*"|[ \t\n]      { BEGIN INITIAL; yyless(0); }
<JUNK>[^/ \t\n]+|.      { log_fmt("NETMAP line %d: unknown character(s) found '%s'\n", yylineno, yytext);  }

%%

/*
 * Editor modelines
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
