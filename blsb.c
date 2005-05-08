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
** NeoStats CVS Identification
** $Id$
*/

#include "neostats.h"
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#include "blsb.h"

Bot *blsb_bot;
int do_set_cb (CmdParams *cmdparams, SET_REASON reason);
static int ss_event_signon (CmdParams* cmdparams);

/** Copyright info */
const char *blsb_copyright[] = {
	"Copyright (c) 1999-2005, NeoStats",
	"http://www.neostats.net/",
	NULL
};

/** Module Info definition 
 * version information about our module
 * This structure is required for your module to load and run on NeoStats
 */
ModuleInfo module_info = {
	"OPSB",
	"An Black List Scanning Bot",
	blsb_copyright,
	blsb_about,
	NEOSTATS_VERSION,
	MODULE_VERSION,
	__DATE__,
	__TIME__,
	MODULE_FLAG_LOCAL_EXCLUDES,
	0,
};

static int blsb_set_exclusions_cb( CmdParams *cmdparams, SET_REASON reason )
{
	if( reason == SET_LOAD || reason == SET_CHANGE )
	{
		SetAllEventFlags( EVENT_FLAG_USE_EXCLUDE, blsb.exclusions );
	}
	return NS_SUCCESS;
}

static bot_cmd blsb_commands[]=
{
	{NULL,		NULL,			0, 	0,		NULL, 		NULL}
};

static bot_setting blsb_settings[]=
{
	{"AKILL",	&blsb.doakill,		SET_TYPE_BOOLEAN,	0,	0,	NS_ULEVEL_ADMIN, 	NULL,	blsb_help_set_akill,	do_set_cb, (void*)1 	},	
	{"AKILLTIME",	&blsb.akilltime,		SET_TYPE_INT,	0,	20736000,NS_ULEVEL_ADMIN, 	NULL,	blsb_help_set_akilltime,	do_set_cb, (void*)86400 	},
	{"CACHETIME",	&blsb.cachetime,		SET_TYPE_INT,	0,	86400,	NS_ULEVEL_ADMIN, 	NULL,	blsb_help_set_cachetime,	do_set_cb, (void*)3600 	},
	{"VERBOSE",	&blsb.verbose,		SET_TYPE_BOOLEAN,	0,	0,	NS_ULEVEL_ADMIN, 	NULL,	blsb_help_set_verbose,	do_set_cb, (void*)1 	},
	{"EXCLUSIONS",	&blsb.exclusions,		SET_TYPE_BOOLEAN,	0,	0,	NS_ULEVEL_ADMIN,	NULL,	blsb_help_set_exclusions,	blsb_set_exclusions_cb, (void *)0 },
	{NULL,		NULL,			0,		0,	0, 	0,		NULL,	NULL,			NULL	},
};

/** BotInfo */
static BotInfo blsb_botinfo = 
{
	"blsb", 
	"blsb1", 
	"blsb", 
	BOT_COMMON_HOST, 
	"BlackList Scanning Bot", 	
	BOT_FLAG_SERVICEBOT|BOT_FLAG_RESTRICT_OPERS|BOT_FLAG_DEAF, 
	blsb_commands, 
	blsb_settings,
};

int do_set_cb (CmdParams *cmdparams, SET_REASON reason) {

	return NS_SUCCESS;
}


/** @brief ModSynch
 *
 *  Startup handler
 *
 *  @param none
 *
 *  @return NS_SUCCESS if suceeds else NS_FAILURE
 */

int ModSynch (void)
{
	SET_SEGV_LOCATION();
	blsb_bot = AddBot (&blsb_botinfo);
	if(blsb.verbose) {
		irc_chanalert (blsb_bot, "Black List Scanning bot has started");
	}
	return NS_SUCCESS;
};

void addtocache(unsigned long ip) 
{
	lnode_t *cachenode;
	cache_entry *ce;

	SET_SEGV_LOCATION();
			
	/* pop off the oldest entry */
	if (list_isfull(cache)) {
		dlog (DEBUG2, "blsb: Deleting Tail of Cache: %d", (int)list_count(cache));
		cachenode = list_del_last(cache);
		ce = lnode_get(cachenode);
		lnode_destroy(cachenode);
		ns_free(ce);
	}
	cachenode = list_first(cache);
	while (cachenode) {
		ce = lnode_get(cachenode);
		if (ce->ip == ip) {
			dlog (DEBUG2,"blsb: Not adding %ld to cache as it already exists", ip);
			return;
		}
		cachenode = list_next(cache, cachenode);
	}
	
	ce = malloc(sizeof(cache_entry));
	ce->ip = ip;
	ce->when = time(NULL);
	lnode_create_append(cache, ce);
}

int checkcache(unsigned long ip) 
{
#if 0
	Client *scanclient;
	lnode_t *node, *node2;
	cache_entry *ce;

	SET_SEGV_LOCATION();
	if( scandata->server )
	{
		scanclient = FindServer(scandata->server);
		if( scanclient && ModIsServerExcluded( scanclient ) )
		{
			return 1;
		}
	}
	if( scandata->who )
	{
		scanclient = FindUser(scandata->who);
		if( scanclient && ModIsUserExcluded( scanclient ) )
		{
			return 2;
		}
	}
	node = list_first(cache);
	while (node) {
		ce = lnode_get(node);
		
		/* delete any old cache entries */
	
		if ((time(NULL) - ce->when) > blsb.cachetime) {
			dlog (DEBUG1, "blsb: Deleting old cache entry %ld", ce->ip);
			node2 = list_next(cache, node);			
			list_delete(cache, node);
			lnode_destroy(node);
			ns_free(ce);
			node = node2;
			break;
		}
		if (ce->ip == scandata->ip.s_addr) {
			dlog (DEBUG1, "blsb: user %s is already in Cache", scandata->who);
			blsb.cachehits++;
			if (scandata->reqclient) 
				irc_prefmsg (blsb_bot, scandata->reqclient, "User %s is already in Cache", scandata->who);
			return 3;
		}
		node = list_next(cache, node);
	}
#endif
	return 0;
}

ModuleEvent module_events[] = 
{
	{ EVENT_NICKIP, 	ss_event_signon, EVENT_FLAG_EXCLUDE_ME},
	{ EVENT_NULL, 	NULL}
};

/* this function kicks of a scan of a user that just signed on the network */
static int ss_event_signon (CmdParams* cmdparams)
{
	return 1;
}

int ModInit( void )
{
	ModuleConfig (blsb_settings);
	/* we have to be careful here. Currently, we have 7 sockets that get opened per connection. Soooo.
	*  we check that MAX_SCANS is not greater than the maxsockets available / 7
	*  this way, we *shouldn't* get problems with running out of sockets 
	*/
	me.want_nickip = 1;
	return NS_SUCCESS;
}

int ModFini( void )
{
	return NS_SUCCESS;
}

#ifdef WIN32 /* temp */

int main (int argc, char **argv)
{
	return 0;
}
#endif
