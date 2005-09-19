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

/*  TODO:
 *  - Akill support.
 *  - Buffer sizes for name and domain should not need to be so big
 *    and should be made a more appropriate size.
 *  - If a remove akill command is added, it must check whether an akill
 *    was added by blsb before removing it otherwise blsb becomes a way
 *    for opers to remove any akill on the network including those they
 *    may not normally have access to.
 *  - Do we need cache support?.
 */

#include "neostats.h"
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#include "blsb.h"

static int event_nickip( CmdParams* cmdparams );
static int blsb_cmd_list( CmdParams* cmdparams );
static int blsb_cmd_add( CmdParams* cmdparams );
static int blsb_cmd_del( CmdParams* cmdparams );
static int blsb_cmd_check( CmdParams* cmdparams );
static int blsb_set_exclusions_cb( CmdParams *cmdparams, SET_REASON reason );
void dnsbl_callback( void *data, adns_answer *a );

Bot *blsb_bot;

static dom_list stddomlist[] =
{
	{"Blitzed_OPM", "opm.blitzed.org", BL_LOOKUP_TXT_RECORD, "Open proxy - see http://opm.blitzed.org/%s"},
	{"Secure-IRC", "bl.irc-chat.net", BL_LOOKUP_TXT_RECORD, "Insecure Host - See http://secure.irc-chat.net/ipinfo.php?ip=%s"},
	{"Tor_Exit_Server", "tor.dnsbl.sectoor.de", BL_LOOKUP_TXT_RECORD, "Your Host is a Tor Exit Server"},
	{"", "", 0}
};

/** Copyright info */
const char *blsb_copyright[] =
{
	"Copyright (c) 1999-2005, NeoStats",
	"http://www.neostats.net/",
	NULL
};

/** Module Info definition 
 *	This describes the module to the NeoStats core and provides information
 *  to end users when modules are queried.
 *  The structure is required but some fields are optional.
 */
ModuleInfo module_info =
{
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

static bot_cmd blsb_commands[]=
{
	{"ADD",		blsb_cmd_add,	4,	NS_ULEVEL_ADMIN,	blsb_help_add},
	{"DEL",		blsb_cmd_del,	1,	NS_ULEVEL_ADMIN,	blsb_help_del},
	{"LIST",	blsb_cmd_list,	0,	NS_ULEVEL_ADMIN,	blsb_help_list},
	{"CHECK",	blsb_cmd_check,	1,	NS_ULEVEL_OPER,		blsb_help_check},
	NS_CMD_END()
};

static bot_setting blsb_settings[]=
{
	{"AKILL",		&blsb.doakill,		SET_TYPE_BOOLEAN,	0,	0,	NS_ULEVEL_ADMIN, 	NULL,	blsb_help_set_akill,	NULL, (void*)1 	},	
	{"AKILLTIME",	&blsb.akilltime,		SET_TYPE_INT,	0,	20736000,NS_ULEVEL_ADMIN, 	NULL,	blsb_help_set_akilltime,	NULL, (void*)TS_ONE_DAY 	},
	{"CACHETIME",	&blsb.cachetime,		SET_TYPE_INT,	0,	TS_ONE_DAY,	NS_ULEVEL_ADMIN, 	NULL,	blsb_help_set_cachetime,	NULL, (void*)TS_ONE_HOUR 	},
	{"VERBOSE",		&blsb.verbose,		SET_TYPE_BOOLEAN,	0,	0,	NS_ULEVEL_ADMIN, 	NULL,	blsb_help_set_verbose,	NULL, (void*)1 	},
	{"EXCLUSIONS",	&blsb.exclusions,		SET_TYPE_BOOLEAN,	0,	0,	NS_ULEVEL_ADMIN,	NULL,	blsb_help_set_exclusions,	blsb_set_exclusions_cb, (void *)0 },
	NS_SETTING_END()
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

/** Module event list
 *  What events we will act on
 */

ModuleEvent module_events[] = 
{
	{ EVENT_NICKIP, event_nickip, EVENT_FLAG_EXCLUDE_ME},
	NS_EVENT_END()
};

/** @brief new_bldomain
 *
 *  Allocate a new blacklist domain entry and add to the list
 *
 *  @param name of service
 *  @param domain of service
 *  @param type of service
 *
 *  @return pointer to newly allocated entry
 */

static dom_list *new_bldomain( char *name, char *domain, BL_LOOKUP_TYPE type, char *msg )
{
	dom_list *dl;

	dl = ns_calloc( sizeof( dom_list ) );
	strlcpy( dl->name, name, BUFSIZE );
	strlcpy( dl->domain, domain, BUFSIZE );
	strlcpy( dl->msg, msg, BUFSIZE );
	dl->type = type;		
	lnode_create_append( blsb.domains, dl );
	DBAStore( "domains", dl->name, (void *)dl, sizeof( dom_list ) );
	return dl;
}

/** @brief dnsbl_callback
 *
 *  DNS callback
 *
 *  @param data
 *  @param a
 *
 *  @return NS_SUCCESS if suceeds else result of command
 */

void dnsbl_callback(void *data, adns_answer *a)
{
	scanclient *sc = (scanclient *)data;
	int i;
	char *show;
	struct in_addr inp;

	if (a && (a->nrrs > 0) && (a->status == adns_s_ok)) {
		for (i = 0; i < a->nrrs; i++) {
			if (a->type == adns_r_a) {
				/* here we should actually check the return IP address and see if we really want to do something with it */
				inp = *((struct in_addr*)&a->rrs.inaddr[i]);
				show = ns_malloc(BUFSIZE);
				ircsnprintf(show, BUFSIZE, sc->domain->msg, sc->ip);
			} if (a->type == adns_r_txt) {
				show = a->rrs.manyistr[i]->str;
			}
			if (blsb.verbose) 
				irc_chanalert( blsb_bot, "%s (%s) exists in %s blacklist: %s", sc->user->name, sc->ip, sc->domain->name, show );
				if (sc->check) 
					irc_prefmsg(blsb_bot, sc->check, "%s (%s) exists in %s blacklist: %s", sc->user->name, sc->ip, sc->domain->name, show);
			if (sc->banned == 0 && sc->user) {
				sc->banned = 1;
				/* only ban/msg the user once */
				irc_prefmsg(blsb_bot, sc->user, "Your Host is listed as a inscure host at %s: %s", sc->domain->name, show);
				if (blsb.doakill) {
					irc_akill (blsb_bot, sc->ip, "*", blsb.akilltime, "Your Host is listed as a insecure host at %s: %s", sc->domain->name, show);
				}
			}
			if (a->type == adns_r_a) ns_free(show);
		}
	} else if (a && (a->status == adns_s_nxdomain)) {
		if (blsb.verbose) 
			irc_chanalert( blsb_bot, "%s (%s) does not exist in %s blacklist", sc->user->name, sc->ip, sc->domain->name);
		if (sc->check) 
			irc_prefmsg(blsb_bot, sc->check, "%s (%s) does not exist in %s blacklist", sc->user->name, sc->ip, sc->domain->name);
	} else if (a->status != adns_s_ok) {
			nlog(LOG_WARNING, "DNS error %s", adns_strerror(a->status));
	}			
}

/** @brief do_lookup
 *
 *  trigger lookups
 *
 *  @param Client *lookupuser
 *  @param Client *reportuser
 *
 *  @return NS_SUCCESS if suceeds else result of command
 */

scanclient *do_lookup( Client *lookupuser, Client *reportuser )
{
	static char ip[HOSTIPLEN];
	static char reverseip[HOSTIPLEN];
	lnode_t *node;
	dom_list *dl;
	scanclient *sc = NULL;
	unsigned char a, b, c, d;
	int buflen;
	d = (unsigned char) ( lookupuser->ip.s_addr >> 24 ) & 0xFF;
	c = (unsigned char) ( lookupuser->ip.s_addr >> 16 ) & 0xFF;
	b = (unsigned char) ( lookupuser->ip.s_addr >> 8 ) & 0xFF;
	a = (unsigned char) ( lookupuser->ip.s_addr & 0xFF );   
	ircsnprintf( ip, HOSTIPLEN, "%d.%d.%d.%d", a, b, c, d );
	ircsnprintf( reverseip, HOSTIPLEN, "%d.%d.%d.%d", d, c, b, a );
	node = list_first( blsb.domains );
	while( node )
	{
		dl = lnode_get( node);
		/* Allocate enough for domain, ip address, additional period and NULL */
		buflen = strlen( dl->domain ) + HOSTIPLEN + 1 + 1;
		sc = ns_malloc( sizeof( scanclient ) );
		sc->check = reportuser;
		sc->user = lookupuser;
		sc->domain = dl;
		sc->banned = 0;
		sc->lookup = ns_malloc( buflen );
		strlcpy( sc->ip, ip, HOSTIPLEN );
		strlcpy( sc->reverseip, reverseip, HOSTIPLEN );
		ircsnprintf( sc->lookup, buflen, "%s.%s", reverseip, dl->domain );
		switch (dl->type)
		{
			case BL_LOOKUP_TXT_RECORD:	/* TXT record */
				dns_lookup( sc->lookup, adns_r_txt, dnsbl_callback, sc );
				break;
			case BL_LOOKUP_A_RECORD: /* A record */
				dns_lookup( sc->lookup, adns_r_a, dnsbl_callback, sc );
				break;
			default:
				nlog( LOG_WARNING, "Unknown Type for DNS BL %s", dl->name );
				break;
		}
        node = list_next( blsb.domains, node );
	}
	return sc;
}

/** @brief blsb_cmd_list
 *
 *  LIST command handler
 *  List entries in the blacklist domain list
 *
 *  @param cmdparam struct
 *
 *  @return NS_SUCCESS if suceeds else result of command
 */

int blsb_cmd_list( CmdParams* cmdparams )
{
	dom_list *dl;
	lnode_t *lnode;

	lnode = list_first(blsb.domains);
	irc_prefmsg (blsb_bot, cmdparams->source, "BlackList domains:");
	while (lnode) {
		dl = lnode_get(lnode);
		irc_prefmsg (blsb_bot, cmdparams->source, "%s: %s (type %d)", dl->domain, dl->name, dl->type);
		lnode = list_next(blsb.domains, lnode);
	}
	irc_prefmsg (blsb_bot, cmdparams->source, "End of list.");
	CommandReport(blsb_bot, "%s requested blacklist domain list", cmdparams->source->name);
	return NS_SUCCESS;
}

/** @brief blsb_cmd_add
 *
 *  ADD command handler
 *  Add an entry to the blacklist domain list
 *
 *  @param cmdparam struct
 *		cmdparams->av[0] = domain
 *		cmdparams->av[1] = type
 *		cmdparams->av[2] = name
 *
 *  @return NS_SUCCESS if suceeds else result of command
 */

int blsb_cmd_add( CmdParams* cmdparams )
{
	dom_list *dl;
	lnode_t *lnode;
	int type;
	char *msg;
	
	if( list_isfull( blsb.domains ) )
	{
		irc_prefmsg( blsb_bot, cmdparams->source, "Error, domain list is full" );
		return NS_FAILURE;
	}
	type = atoi( cmdparams->av[1] );
	if( type <= BL_LOOKUP_TYPE_MIN || type >= BL_LOOKUP_TYPE_MAX )
	{
		irc_prefmsg( blsb_bot, cmdparams->source, "type field does not contain a valid type" );
		return NS_FAILURE;
	}
	msg = joinbuf( cmdparams->av, cmdparams->ac, 3 );
	/* XXX do a initial lookup on the domain to check it exists? */

	/* check for duplicates */
	lnode = list_first( blsb.domains );
	while( lnode )
	{
		dl = lnode_get( lnode );
		if( ( !ircstrcasecmp( dl->name, cmdparams->av[2] ) ) || ( !ircstrcasecmp(dl->domain, cmdparams->av[0] ) ) )
		{
			irc_prefmsg( blsb_bot, cmdparams->source, "%s already has an entry", cmdparams->av[0] );
			return NS_SUCCESS;
		}
		lnode = list_next(blsb.domains, lnode);
	}
	dl = new_bldomain( cmdparams->av[2], cmdparams->av[0], type, msg );
	irc_prefmsg( blsb_bot, cmdparams->source, "Added domain %s (%s) as type %d", dl->name, dl->domain, dl->type );
	CommandReport( blsb_bot, "%s added domain %s (%s) as type %d", cmdparams->source->name, dl->name, dl->domain, dl->type );
	return NS_SUCCESS;
}

/** @brief blsb_cmd_del
 *
 *  DEL command handler
 *  deletes an entry from the blacklist domain list
 *
 *  @param cmdparam struct
 *		cmdparams->av[0] = domain
 *
 *  @return NS_SUCCESS if suceeds else result of command
 */

int blsb_cmd_del( CmdParams* cmdparams ) 
{
	dom_list *dl;
	lnode_t *lnode;

	lnode = list_first(blsb.domains);
	while (lnode) {
		dl = lnode_get(lnode);
		if( ircstrcasecmp( dl->domain, cmdparams->av[0] ) == 0 )
		{
			list_delete(blsb.domains, lnode);
			lnode_destroy(lnode);
			irc_prefmsg (blsb_bot, cmdparams->source, "Deleted %s (%s) from blacklist domains", dl->name, dl->domain);
			CommandReport(blsb_bot, "%s deleted %s (%s) from blacklist domains", cmdparams->source->name, dl->name, dl->domain);
			DBADelete("domains", dl->name);
			ns_free(dl);
			return NS_SUCCESS;
		}
		lnode = list_next(blsb.domains, lnode);
	}		
	/* if we get here, then we can't find the entry */
	irc_prefmsg (blsb_bot, cmdparams->source, "Error, no entry for %s", cmdparams->av[0]);
	return NS_FAILURE;
}

/** @brief blsb_cmd_check
 *
 *  CHECK command handler
 *
 *  @param cmdparam struct
 *
 *  @return NS_SUCCESS if suceeds else result of command
 */

int blsb_cmd_check( CmdParams* cmdparams )
{
	scanclient *sc = NULL;
	Client *user;
	
	user = FindUser(cmdparams->av[0]);
	if (!user)
	{
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
		irc_prefmsg(blsb_bot, cmdparams->source, "Can not find %s online", cmdparams->av[0]);
		return NS_ERR_SYNTAX_ERROR;
	}
	sc = do_lookup( user, cmdparams->source );
	if( sc )
	{
		irc_prefmsg( blsb_bot, cmdparams->source, "Checking %s (%s) against DNS Blacklists", sc->user->name, sc->ip );
		CommandReport( blsb_bot, "%s is checking %s (%s) against DNS Blacklists", cmdparams->source->name, sc->user->name, sc->ip );
	}
	return NS_SUCCESS;
}

/** @brief event_nickip
 *
 *  NICKIP event handler
 *  scan user that just signed on the network
 *
 *  @cmdparams pointer to commands param struct
 *
 *  @return NS_SUCCESS if suceeds else NS_FAILURE
 */

static int event_nickip( CmdParams* cmdparams )
{
	SET_SEGV_LOCATION();
	if (ModIsServerExcluded(cmdparams->source->uplink))
		return NS_SUCCESS;
	if (IsNetSplit(cmdparams->source))
		return NS_SUCCESS;
	do_lookup( cmdparams->source, NULL );
	return NS_SUCCESS;
}

/** @brief load_dom
 *
 *  Database load domains row callback handler
 *
 *  @param pointer to loaded data
 *  @param size of loaded data
 *
 *  @return NS_FALSE
 */

static int load_dom( void *data, int size )
{
	dom_list *dl;

	dl = ns_calloc( sizeof(dom_list));
	os_memcpy(dl, data, sizeof (dom_list));
	lnode_create_append(blsb.domains, dl);
	return NS_FALSE;
}

/** @brief load_default_bldomains
 *
 *  Load default domain settings
 *
 *  @param none
 *
 *  @return none
 */

static void load_default_bldomains( void )
{
	dom_list *dl;
	dom_list *default_domains;

	default_domains = stddomlist;
	while( default_domains->type != BL_LOOKUP_TYPE_MIN )
	{
		dl = new_bldomain( default_domains->name, default_domains->domain, default_domains->type, default_domains->msg );
		default_domains++;
	}
}

/** @brief ModInit
 *
 *  Init handler
 *
 *  @param none
 *
 *  @return NS_SUCCESS if suceeds else NS_FAILURE
 */

int ModInit( void )
{
	ModuleConfig( blsb_settings );
	blsb.domains = list_create( -1 );
	me.want_nickip = 1;
	if( !blsb.domains ) {
		nlog( LOG_CRITICAL, "Unable to create domain list" );
		return NS_FAILURE;
	}
	DBAFetchRows( "domains", load_dom );
	/* If no domains, this must be our first run so load defaults */
	if( list_count( blsb.domains ) == 0 )
		load_default_bldomains();
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

/** @brief ModFini
 *
 *  Fini handler
 *
 *  @param none
 *
 *  @return NS_SUCCESS if suceeds else NS_FAILURE
 */

int ModFini( void )
{
	return NS_SUCCESS;
}

/** @brief blsb_set_exclusions_cb
 *
 *  Set callback for exclusions
 *  Enable or disable exclude event flag
 *
 *  @cmdparams pointer to commands param struct
 *  @cmdparams reason for SET
 *
 *  @return NS_SUCCESS if suceeds else NS_FAILURE
 */

static int blsb_set_exclusions_cb( CmdParams *cmdparams, SET_REASON reason )
{
	if( reason == SET_LOAD || reason == SET_CHANGE )
	{
		SetAllEventFlags( EVENT_FLAG_USE_EXCLUDE, blsb.exclusions );
	}
	return NS_SUCCESS;
}
