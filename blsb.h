/* NeoStats - IRC Statistical Services 
** Copyright (c) 1999-2005 Adam Rutter, Justin Hammond, Mark Hetherington
** http://www.neostats.net/
**
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation; either version 2 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program; if not, write to the Free Software
**  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
**  USA
**
** NetStats CVS Identification
** $Id$
*/


#ifndef BLSB_H
#define BLSB_H

#include MODULECONFIG

typedef enum BL_LOOKUP_TYPE
{
	BL_LOOKUP_TYPE_MIN = 0,
	BL_LOOKUP_TXT_RECORD,
	BL_LOOKUP_A_RECORD,
	BL_LOOKUP_TYPE_MAX
}BL_LOOKUP_TYPE;

typedef struct dom_list {
	char name[BUFSIZE];
	char domain[BUFSIZE];
	BL_LOOKUP_TYPE type;
	char msg[BUFSIZE];
	int noban;
} dom_list;

typedef struct scanclient {
	char usernick[MAXNICK];
	char username[MAXUSER];
	char hostname[MAXHOST];
	int exclude;
	dom_list *domain;
	char checknick[MAXNICK];
	char reverseip[HOSTIPLEN];
	char ip[HOSTIPLEN];
	char *lookup;
	int banned;
} scanclient;

/* blsb_help.c */
extern const char *blsb_about[];
extern const char *blsb_help_add[];
extern const char *blsb_help_del[];
extern const char *blsb_help_list[];
extern const char *blsb_help_check[];
extern const char *blsb_help_set_akill[];
extern const char *blsb_help_set_akilltime[];
extern const char *blsb_help_set_verbose[];
extern const char *blsb_help_set_exclusions[];

#endif /* BLSB_H */
