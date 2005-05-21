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


#ifndef blsb_H
#define blsb_H

#ifdef WIN32
#include "modconfigwin32.h"
#else
#include "modconfig.h"
#endif


extern Bot *blsb_bot;

struct blsb {
	int akilltime;
	int cachetime;
	int cachehits;
	int doakill;
	int verbose;
	int exclusions;
	list_t *domains;
} blsb;

typedef struct cache_entry {
	unsigned long ip;
	time_t when;
} cache_entry;

/* this is a list of cached scans */
list_t *cache;

typedef struct dom_list {
	char name[BUFSIZE];
	char domain[BUFSIZE];
	int type;
} dom_list;

typedef struct scanclient {
	Client *user;
	dom_list *domain;
	Client *check;
	char *lookup;
} scanclient;


/* blsb_help.c */
extern const char *blsb_help_set_akill[];
extern const char *blsb_help_set_akilltime[];
extern const char *blsb_help_set_cachetime[];
extern const char *blsb_help_set_verbose[];
extern const char *blsb_help_set_exclusions[];
extern const char blsb_help_domains_add_oneline[];
extern const char blsb_help_domains_del_oneline[];
extern const char blsb_help_domains_list_oneline[];
extern const char *blsb_help_domains_add[];
extern const char *blsb_help_domains_del[];
extern const char *blsb_help_domains_list[];
extern const char *blsb_about[];
extern const char *blsb_help_check[];
extern const char blsb_help_check_oneline[];

#endif /* blsb_H */
