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
static int ss_event_signon( CmdParams* cmdparams );
int blsb_cmd_domains_list( CmdParams* cmdparams );
int blsb_cmd_domains_add( CmdParams* cmdparams );
int blsb_cmd_domains_del( CmdParams* cmdparams );
int blsb_cmd_domains (CmdParams* cmdparams);
int blsb_cmd_check (CmdParams* cmdparams);
void dnsbl_callback(void *data, adns_answer *a);

static dom_list stddomlist[] = {
	{"Blitzed OPM", "opm.blitzed.org", 1},
	{"Secure IRC", "bl.irc-chat.net", 1},
	{"Tor Exit Server", "tor.dnsbl.sectoor.de", 1},
	{"", "", 0}
};

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
	"BLSB",
	"Black List Scanning Bot",
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
	{"ADD",		blsb_cmd_domains_add,	3,	NS_ULEVEL_ADMIN,	blsb_help_domains_add, blsb_help_domains_add_oneline},
	{"DEL",		blsb_cmd_domains_del,	1,	NS_ULEVEL_ADMIN,	blsb_help_domains_del, blsb_help_domains_del_oneline},
	{"LIST",	blsb_cmd_domains_list,	0,	NS_ULEVEL_ADMIN,	blsb_help_domains_list, blsb_help_domains_list_oneline},
	{"CHECK",	blsb_cmd_check,		1,	NS_ULEVEL_OPER,	blsb_help_check,	 blsb_help_check_oneline},
	{NULL,		NULL,			0, 	0,		NULL, 		NULL}
};

static bot_setting blsb_settings[]=
{
	{"AKILL",	&blsb.doakill,		SET_TYPE_BOOLEAN,	0,	0,	NS_ULEVEL_ADMIN, 	NULL,	blsb_help_set_akill,	NULL, (void*)1 	},	
	{"AKILLTIME",	&blsb.akilltime,		SET_TYPE_INT,	0,	20736000,NS_ULEVEL_ADMIN, 	NULL,	blsb_help_set_akilltime,	NULL, (void*)86400 	},
	{"CACHETIME",	&blsb.cachetime,		SET_TYPE_INT,	0,	86400,	NS_ULEVEL_ADMIN, 	NULL,	blsb_help_set_cachetime,	NULL, (void*)3600 	},
	{"VERBOSE",	&blsb.verbose,		SET_TYPE_BOOLEAN,	0,	0,	NS_ULEVEL_ADMIN, 	NULL,	blsb_help_set_verbose,	NULL, (void*)1 	},
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

ModuleEvent module_events[] = 
{
	{ EVENT_NICKIP, 	ss_event_signon, EVENT_FLAG_EXCLUDE_ME},
	{ EVENT_NULL, 	NULL}
};

int blsb_cmd_domains_list (CmdParams* cmdparams) 
{
	dom_list *dl;
	int i;
	lnode_t *lnode;

	lnode = list_first(blsb.domains);
	i = 1;
	irc_prefmsg (blsb_bot, cmdparams->source, "BlackList Domains Listing:");
	while (lnode) {
		dl = lnode_get(lnode);
		irc_prefmsg (blsb_bot, cmdparams->source, "%d) %s Domain: %s Type: %d", i, dl->name, dl->domain, dl->type);
		++i;
		lnode = list_next(blsb.domains, lnode);
	}
	irc_prefmsg (blsb_bot, cmdparams->source, "End of list.");
	CommandReport(blsb_bot, "%s requested BlackList Domain Listing", cmdparams->source->name);
	return NS_SUCCESS;
}

/* ./msg blsb domains add <name> <type> <domain> */
int blsb_cmd_domains_add (CmdParams* cmdparams) 
{
	dom_list *dl;
	lnode_t *lnode;

	if (cmdparams->ac < 3) {
		return NS_ERR_SYNTAX_ERROR;
	}
	if (list_isfull(blsb.domains)) {
		irc_prefmsg (blsb_bot, cmdparams->source, "Error, Domains list is full");
		return NS_SUCCESS;
	}
	if (!atoi(cmdparams->av[2])) {
		irc_prefmsg (blsb_bot, cmdparams->source, "type field does not contain a valid type");
		return NS_SUCCESS;
	}
	/* XXX do a initial lookup on the domain to check it exists? */

	/* check for duplicates */
	lnode = list_first(blsb.domains);
	while (lnode) {
		dl = lnode_get(lnode);
		if ((!ircstrcasecmp(dl->name, cmdparams->av[1])) || (!ircstrcasecmp(dl->domain, cmdparams->av[3]))) {
			irc_prefmsg (blsb_bot, cmdparams->source, "Duplicate Entry for Domain %s", cmdparams->av[1]);
			return NS_SUCCESS;
		}
		lnode = list_next(blsb.domains, lnode);
	}
	dl = malloc(sizeof(dom_list));
	strlcpy(dl->name, cmdparams->av[1], BUFSIZE);
	strlcpy(dl->domain, cmdparams->av[3], BUFSIZE);
	dl->type = atoi(cmdparams->av[2]);
		
	lnode_create_append(blsb.domains, dl);
	DBAStore("domains", dl->name, (void *)dl, sizeof(dom_list));
	irc_prefmsg (blsb_bot, cmdparams->source, "Added Domain %s(%s) as type %d to Domains list", dl->name, dl->domain, dl->type);
	CommandReport(blsb_bot, "%s added Domain %s(%s) as type %d to Domains list", cmdparams->source->name, dl->name, dl->domain, dl->type);
	return NS_SUCCESS;
}

int blsb_cmd_domains_del (CmdParams* cmdparams) 
{
	dom_list *dl;
	int i;
	lnode_t *lnode;

	if (cmdparams->ac < 1) {
		return NS_ERR_SYNTAX_ERROR;
	}
	if (atoi(cmdparams->av[1]) != 0) {
		lnode = list_first(blsb.domains);
		i = 1;
		while (lnode) {
			if (i == atoi(cmdparams->av[1])) {
				/* delete the entry */
				dl = lnode_get(lnode);
				list_delete(blsb.domains, lnode);
				lnode_destroy(lnode);
				irc_prefmsg (blsb_bot, cmdparams->source, "Deleted Blacklist Domain %s (%s) out of domains list", dl->name, dl->domain);
				CommandReport(blsb_bot, "%s deleted Blacklist Domain %s (%s) out of domains list", cmdparams->source->name, dl->name, dl->domain);
				DBADelete("domains", dl->name);
				ns_free(dl);
				/* just to be sure, lets sort the list */
				return 1;
			}
			++i;
			lnode = list_next(blsb.domains, lnode);
		}		
		/* if we get here, then we can't find the entry */
		irc_prefmsg (blsb_bot, cmdparams->source, "Error, Can't find entry %d. /msg %s domains list", atoi(cmdparams->av[1]), blsb_bot->name);
	} else {
		irc_prefmsg (blsb_bot, cmdparams->source, "Error, Out of Range");
	}
	return NS_SUCCESS;
}

int blsb_cmd_check (CmdParams* cmdparams) 
{
	Client *user;
	lnode_t *node;
	dom_list *dl;
	scanclient *sc = NULL;
	unsigned char a, b, c, d;
	int buflen;
	
	
	user = FindUser(cmdparams->av[0]);
	if (!user) {
#if 0
/* XXX TODO: Lookup Hostname */
		if (!ValidateHost(cmdparams->av[0]) {
			irc_prefmsg(blsb_bot, cmdparams->source, "Invalid Nick or Host");
			return NS_FAILURE;
		} else {
		         sc = ns_malloc(sizeof(scanclient));
		         sc->check = 1;
		         sc->user = cmdparams->source;
		         sc->domain = dl;
		         sc->lookup = ns_malloc(buflen);
	         ircsnprintf(sc->lookup, buflen, "%d.%d.%d.%d.%s", d, c, b, a, dl->domain);
#endif
		irc_prefmsg(blsb_bot, cmdparams->source, "Can not find %s online\n", cmdparams->av[0]);
		return NS_ERR_SYNTAX_ERROR;
	}
	d = (unsigned char) (user->ip.s_addr >> 24) & 0xFF;
         c = (unsigned char) (user->ip.s_addr >> 16) & 0xFF;
         b = (unsigned char) (user->ip.s_addr >> 8) & 0xFF;
         a = (unsigned char) (user->ip.s_addr & 0xFF);   

         node = list_first(blsb.domains);
         while (node) {
         	dl = lnode_get(node);
	         buflen = 18 + strlen(dl->domain);
	         sc = ns_malloc(sizeof(scanclient));
	         sc->check = cmdparams->source;
	         sc->user = user;
	         sc->domain = dl;
	         sc->lookup = ns_malloc(buflen);
	         ircsnprintf(sc->lookup, buflen, "%d.%d.%d.%d.%s", d, c, b, a, dl->domain);
	         switch (dl->type) {
	         	case 1:	/* TXT record */
			         dns_lookup(sc->lookup, adns_r_txt, dnsbl_callback, sc);
			         break;
			case 2: /* A record */
				dns_lookup(sc->lookup, adns_r_a, dnsbl_callback, sc);
				break;
			default:
				nlog(LOG_WARNING, "Unknown Type for DNS BL %s", dl->name);
				break;
		}
	         node = list_next(blsb.domains, node);
	}
	if (sc) {
		irc_prefmsg (blsb_bot, cmdparams->source, "Checking %s (%d.%d.%d.%d) against DNS Blacklists", sc->user->name, a, b, c, d);
		CommandReport(blsb_bot, "%s is checking %s (%d.%d.%d.%d) against DNS Blacklists", cmdparams->source->name, sc->user->name, a, b, c, d);
	}
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
	if( !blsb_bot )
		return NS_FAILURE;
	if( blsb.verbose )
		irc_chanalert (blsb_bot, "Black List Scanning bot has started");
	return NS_SUCCESS;
}

void dnsbl_callback(void *data, adns_answer *a) {
	scanclient *sc = (scanclient *)data;
	int len, i, ri;
	char *show;

	if (a && a->nrrs > 0) {
		adns_rr_info(a->type, 0, 0, &len, 0, 0);
		for(i = 0; i < a->nrrs;  i++) {
			ri = adns_rr_info(a->type, 0, 0, 0, a->rrs.bytes +i*len, &show);
			if (!ri) {
				if (blsb.verbose) CommandReport(blsb_bot, "%s exists in %s blacklist: %s", sc->user->name, sc->domain->name, show);
				if (sc->check) irc_prefmsg(blsb_bot, sc->check, "%s exists in %s blacklist: %s", sc->user->name, sc->domain->name, show);
				/* XXX AKILL */
			} else {
				nlog(LOG_WARNING, "DNS error %s", adns_strerror(ri));
			}
			ns_free(show);
		}
	} else {
		if (blsb.verbose) CommandReport(blsb_bot, "%s does not exist in %s blacklist", sc->user->name, sc->domain->name);
		if (sc->check) irc_prefmsg(blsb_bot, sc->check, "%s does not exist in %s blacklist", sc->user->name, sc->domain->name);
		dlog(DEBUG3, "No Record for %s", sc->lookup);
	}

}


/* this function kicks of a scan of a user that just signed on the network */
static int ss_event_signon (CmdParams* cmdparams)
{
	dom_list *dl;
	lnode_t *node;
	unsigned char a, b, c, d;
	int buflen;
	scanclient *sc;
	
	SET_SEGV_LOCATION();
	
	if (ModIsServerExcluded(cmdparams->source->uplink)) {
		return NS_SUCCESS;
	}
	
	if (IsNetSplit(cmdparams->source)) {
		return NS_SUCCESS;
	}

	d = (unsigned char) (cmdparams->source->ip.s_addr >> 24) & 0xFF;
	c = (unsigned char) (cmdparams->source->ip.s_addr >> 16) & 0xFF;
	b = (unsigned char) (cmdparams->source->ip.s_addr >> 8) & 0xFF;
	a = (unsigned char) (cmdparams->source->ip.s_addr & 0xFF);

	node = list_first(blsb.domains);
	while (node) {
		dl = lnode_get(node);
		buflen = 18 + strlen(dl->domain);
		sc = ns_malloc(sizeof(scanclient));
		sc->check = NULL;
		sc->user = cmdparams->source;
		sc->domain = dl;
		sc->lookup = ns_malloc(buflen);
		ircsnprintf(sc->lookup, buflen, "%d.%d.%d.%d.%s", d, c, b, a, dl->domain);
		switch (dl->type) {
			case 1:	/* TXT record */
				dns_lookup(sc->lookup, adns_r_txt, dnsbl_callback, sc);
				break;
			case 2: /* A record */
				dns_lookup(sc->lookup, adns_r_a, dnsbl_callback, sc);
				break;
			default:
				nlog(LOG_WARNING, "Unknown Type for DNS BL %s", dl->name);
				break;
		}
		node = list_next(blsb.domains, node);
	}

	return NS_SUCCESS;
}

int load_dom( void *data, int size) {
	dom_list *dl;

	dl = ns_calloc( sizeof(dom_list));
	os_memcpy(dl, data, sizeof (dom_list));
	lnode_create_append(blsb.domains, dl);
	return NS_FALSE;
}

int ModInit( void )
{
	int i;
	dom_list *dl;
	ModuleConfig (blsb_settings);
	blsb.domains = list_create(-1);
	DBAFetchRows("domains", load_dom);
	if (list_count(blsb.domains) == 0) {
		for (i = 0; stddomlist[i].type != 0; i++) {
			dl = ns_malloc(sizeof(dom_list));
			strlcpy(dl->name, stddomlist[i].name, BUFSIZE);
			strlcpy(dl->domain, stddomlist[i].domain, BUFSIZE);
			dl->type = stddomlist[i].type;
			/* Isn't this store pointless since we just loaded the entry anyway??? */
			DBAStore("domains", dl->name, (void *)dl, sizeof(dom_list));
			lnode_create_append(blsb.domains, dl);
		}
	}
	return NS_SUCCESS;
}

int ModFini( void )
{
	return NS_SUCCESS;
}
