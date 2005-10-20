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

const char *blsb_about[] = {
	"\2BLSB\2",
	"",
	"Checks clients against external blacklists as",
	"they connect to the network.",
	NULL
};

const char *blsb_help_check[] = {
	"Scan a user",
	"Syntax: \2CHECK <nick|ip|hostname>\2",
	"",
	"Scan a user connected to your network, an IP address, or a",
	"hostname for insecure proxies and report the status. Any",
	"insecure proxy found, will be banned from the network.",
	NULL
};

const char *blsb_help_add[] = {
	"Add to the blacklist domains",
	"Syntax: \2ADD <domain> <type> <name>\2",
	"",
	"Add a domain to the blacklist lookup list",
	"<type> 1 for TXT record lookups",
	"       2 for A record lookups",
	"<domain> domain for lookups, e.g. opm.blitzed.org",
	"<name> name to assign to this entry, e.g. Blitzed OPM",
	NULL
};

const char *blsb_help_del[] = {
	"Delete from the blacklist domains",
	"Syntax: \2DEL <domain>\2",
	"",
	"Delete entry matching <domain> from the list of blacklist domains",
	NULL
};

const char *blsb_help_list[] = {
	"List the blacklist domains",
	"Syntax: \2LIST\2",
	"",
	"List the current domains used for lookups",
	NULL
};

const char *blsb_help_set_akill [] = {
	"\2AKILL <ON|OFF>\2",
	"Whether to issue an akill for positive lookups",
	NULL
};

const char *blsb_help_set_akilltime [] = {
	"\2AKILLTIME <time>\2",
	"How long the user will be banned from the network",
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
