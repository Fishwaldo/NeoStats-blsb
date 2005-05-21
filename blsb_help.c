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

const char blsb_help_domains_add_oneline[] = "Add to the blacklist domains";
const char blsb_help_domains_del_oneline[] = "Delete from the blacklist domains";
const char blsb_help_domains_list_oneline[] = "List the blacklist domains";
const char blsb_help_status_oneline[] = "View blsb state information";
const char blsb_help_remove_oneline[] = "Remove an akill set by blsb";
const char blsb_help_check_oneline[] = "Scan a selected user";

const char *blsb_about[] = {
	"\2Open Proxy Scanning Bot Information\2",
	"",
	"This service scans clients connecting to this network for",
	"insecure proxies. Insecure proxies are often used to attack",
	"networks or channels with clone bots. If you have a firewall,",
	"or IDS software, please ignore any errors that this scan",
	"may generate.",
	"",
	"If you have any further questions, please contact network",
	"administration.",
	NULL
};

const char *blsb_help_check[] = {
	"Syntax: \2CHECK <nick|ip|hostname>\2",
	"",
	"This option will scan either a user connected to your",
	"network, an IP address, or Hostname for Insecure proxies,",
	"and report the status to you. If an Insecure proxy is",
	"found, the host will be banned from the network",
	NULL
};

const char *blsb_help_status[] = {
	"Syntax: \2STATUS\2",
	"",
	"Display status of the open proxy scanning bot",
	NULL
};

const char *blsb_help_set_akill [] = {
	"\2AKILL <ON|OFF>\2",
	"Whether to issue an akill for positive lookups",
	NULL
};

const char *blsb_help_set_akilltime [] = {
	"\2AKILLTIME <time>\2",
	"How long the user will be banned from the network for",
	NULL
};

const char *blsb_help_set_cachetime [] = {
	"\2CACHETIME <time>\2",
	"Time (in seconds) that an entry will be cached",
	NULL
};

const char *blsb_help_set_verbose [] = {
	"\2VERBOSE <ON|OFF>\2",
	"Whether blsb is verbose in operation or not",
	NULL
};

const char *blsb_help_set_exclusions[] = {
	"\2EXCLUSIONS <ON|OFF>\2",
	"Use global exclusion list in addition to local exclusion list",
	NULL
};

const char *blsb_help_domains_add[] = {
	"Syntax: \2ADD <NAME> <TYPE> <DOMAIN>\2",
	"",
	"\2ADD\2 will add a domain to the blacklist lookup list",
	NULL
};

const char *blsb_help_domains_del[] = {
	"Syntax: \2DEL <index>\2",
	"",
	"Delete entry <index> from the list of domains used for lookups",
	NULL
};

const char *blsb_help_domains_list[] = {
	"Syntax: \2LIST\2",
	"",
	"List the current domains used for lookups",
	NULL
};

const char *blsb_help_remove[] = {
	"Syntax: \2REMOVE <ip|hostname>\2",
	"",
	"Remove akills that have been set by blsb.",
	"",
	"<ip|hostname> is the hostname listed in your akill list",
	"(usually found with /stats a)",
	NULL
};
