/*******************************************************************************/
/*                                                                             */
/*  Copyright 2004-2017 Pascal Gloor                                                */
/*                                                                             */
/*  Licensed under the Apache License, Version 2.0 (the "License");            */
/*  you may not use this file except in compliance with the License.           */
/*  You may obtain a copy of the License at                                    */
/*                                                                             */
/*     http://www.apache.org/licenses/LICENSE-2.0                              */
/*                                                                             */
/*  Unless required by applicable law or agreed to in writing, software        */
/*  distributed under the License is distributed on an "AS IS" BASIS,          */
/*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   */
/*  See the License for the specific language governing permissions and        */
/*  limitations under the License.                                             */
/*                                                                             */
/*******************************************************************************/

// PATCH : SQLITE3 writer 

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>

#include <p_defs.h>
#include <p_sqldump.h>
#include <p_tools.h>
#include <stdlib.h>
#include <log.h>

#define LOGFD  peer[id].logfd 

static void exitOnError(FILE * logfd, sqlite3 * db, const char * where, int sqerr)
{
    if (sqerr!=SQLITE_OK && sqerr != SQLITE_ROW && sqerr != SQLITE_DONE )
	{
		log_error(logfd,"ERROR!! at %s", where);
		log_error(logfd,"      > sql code       %d",sqerr);
		log_error(logfd,"      > sql error      %d",sqlite3_errcode(db));
		log_error(logfd,"      > sql exterror   %d",sqlite3_extended_errcode(db));
		log_error(logfd,"      > sql msg        %s",sqlite3_errmsg(db));
		log_error(logfd,"      > sql errstring  %s",sqlite3_errstr(sqerr));
		log_error(logfd,"Sorry, have to quit (-2), bye");
		sqlite3_close(db);
		exit(-2);
	}
}

static int  returnOnError(FILE * logfd, sqlite3 * db, const char * where, int sqerr, sqlite3_stmt * pstmt)
{
    if (sqerr!=SQLITE_OK && sqerr != SQLITE_ROW && sqerr != SQLITE_DONE )
	{
		log_error(logfd,"WARNING!! at %s", where);
		log_error(logfd,"      > sql code       %d",sqerr);
		log_error(logfd,"      > sql error      %d",sqlite3_errcode(db));
		log_error(logfd,"      > sql exterror   %d",sqlite3_extended_errcode(db));
		log_error(logfd,"      > sql msg        %s",sqlite3_errmsg(db));
		log_error(logfd,"      > sql errstring  %s",sqlite3_errstr(sqerr));
		if (pstmt) 
			sqlite3_finalize(pstmt);
		return 1;
	} else {
		return 0;
	}
}


/* opening file */
void p_sqldump_open_file(struct peer_t *peer, int id, struct timeval *ts)
{
	int sqerr = SQLITE_OK;
	sqlite3 * pSQL3=NULL;
	sqlite3_stmt  * pstmt=NULL;

	snprintf(peer[id].sqldbname, sizeof(peer[id].sqldbname), "%s/%s_routes.db.sqlite3",
		DUMPDIR,
		peer[id].af == 4 ? p_tools_ip4str(id, &peer[id].ip4) : p_tools_ip6str(id, &peer[id].ip6));

	#ifdef DEBUG
	printf("opening '%s'\n",peer[id].sqldbname);
	#endif

	struct stat sb;
	if ( stat(DUMPDIR, &sb) == -1 )
	{
		mkdir(DUMPDIR, 0755);
	}


	/* create log file upfront for this peer, we need this to run in prodn */
	char logfile[256];
	snprintf(logfile, sizeof(logfile),"%s/log.%s",
		PEERLOGDIR,
		peer[id].af == 4 ? p_tools_ip4str(id, &peer[id].ip4) : p_tools_ip6str(id, &peer[id].ip6));

	peer[id].logfd = fopen(logfile, "wb" );
	log_info( LOGFD ,  "Opened log file for peer %s", 
		peer[id].af == 4 ? p_tools_ip4str(id, &peer[id].ip4) : p_tools_ip6str(id, &peer[id].ip6));


	sqerr = sqlite3_open_v2( peer[id].sqldbname, &pSQL3, SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL);
	exitOnError(LOGFD,pSQL3, "open", sqerr);
	sqlite3_busy_timeout(pSQL3, 10000);
	sqerr = sqlite3_exec( pSQL3, "BEGIN TRANSACTION", NULL, NULL, NULL );

	// prefix -> as path, the current view 
	sqerr=sqlite3_exec(pSQL3, "CREATE TABLE IF NOT EXISTS PREFIX_PATHS_V4 (    "
                        "    PREFIX 					VARCHAR PRIMARY KEY,    "
                        "    ASPATH						VARCHAR,    "
                        "    COMMUNITYPATH	 			VARCHAR,    "
						"    NEXTHOP					VARCHAR,    "
                        "    TIMESTAMP	 				INTEGER     "
						"    );", NULL,NULL,NULL);
	exitOnError(LOGFD,pSQL3, "create table prefix_paths_v4", sqerr);

	// prefix-v6 -> as path, the current view 
	sqerr=sqlite3_exec(pSQL3, "CREATE TABLE IF NOT EXISTS PREFIX_PATHS_V6 (    "
                        "    PREFIX 					VARCHAR PRIMARY KEY,    "
                        "    ASPATH						VARCHAR,    "
                        "    COMMUNITYPATH	 			VARCHAR,    "
						"    NEXTHOP					VARCHAR,    "
                        "    TIMESTAMP	 				INTEGER     "
						"    );", NULL,NULL,NULL);
	exitOnError(LOGFD,pSQL3, "create table prefix_paths_v6", sqerr);

	// last keep alive 
	sqerr=sqlite3_exec(pSQL3, "CREATE TABLE IF NOT EXISTS LAST_KEEPALIVE (    "
                        "    TIMESTAMP  INTEGER    "
						"    );", NULL,NULL,NULL);
	exitOnError(LOGFD,pSQL3, "create table last_keepalive", sqerr);

	// connection events 
	sqerr=sqlite3_exec(pSQL3, "CREATE TABLE IF NOT EXISTS EVENTS  (    "
                        "    TIMESTAMP  	INTEGER,    "
                        "    DESCRIPTION	VARCHAR     "
						"    );", NULL,NULL,NULL);
	exitOnError(LOGFD,pSQL3, "create table session_events", sqerr);

	// peer table 
	sqerr=sqlite3_exec(pSQL3, "CREATE TABLE IF NOT EXISTS PEER_INFO (    "
                        "    ADDRESS  	    VARCHAR PRIMARY KEY,    "
                        "    DESCRIPTION	VARCHAR     "
						"    );", NULL,NULL,NULL);
	exitOnError(LOGFD,pSQL3, "create table peerinfo", sqerr);


	// insert peer info 
	sqerr = sqlite3_prepare_v2( pSQL3,
		"INSERT OR REPLACE INTO PEER_INFO (ADDRESS, DESCRIPTION) VALUES (?,?); ",
		-1, &pstmt, NULL);
	exitOnError(LOGFD,pSQL3, "insert/peerinfo/prepare",  sqerr);

	sqerr = sqlite3_bind_text(pstmt, 1, 
								(peer[id].af == 4 ? p_tools_ip4str(id, &peer[id].ip4) : p_tools_ip6str(id, &peer[id].ip6)),
								-1, NULL );
	sqerr = sqlite3_bind_text(pstmt, 2, "peer inserted", -1, NULL);

	sqerr = sqlite3_step( pstmt);
	exitOnError(LOGFD,pSQL3, "insert/peerinfo/step",  sqerr);

	sqerr = sqlite3_finalize( pstmt);
	exitOnError(LOGFD,pSQL3, "inser/peerinfo/finalize",  sqerr);

	sqerr = sqlite3_exec( pSQL3, "COMMIT TRANSACTION", NULL, NULL, NULL );
	sqlite3_close(pSQL3);

	log_info( LOGFD ,  "Created required tables" );
}

/* log keepalive msg */
void p_sqldump_add_keepalive(struct peer_t *peer, int id, struct timeval *ts)
{
	int sqerr = SQLITE_OK;
	sqlite3 * pSQL3=NULL;
	sqlite3_stmt  * pstmt=NULL;

	p_sqldump_check_file(peer,id,ts);

	sqerr = sqlite3_open_v2( peer[id].sqldbname, &pSQL3, SQLITE_OPEN_READWRITE, NULL);
	if (returnOnError(LOGFD,pSQL3, "keepalive/open", sqerr,NULL)) return;

	sqlite3_busy_timeout(pSQL3, 10000);
	sqerr = sqlite3_exec( pSQL3, "BEGIN TRANSACTION", NULL, NULL, NULL );

	// retain structure as much as possible from p_dump so fill this msg 
	struct dump_msg msg;
	msg.ts   = ((uint64_t)ts->tv_sec);

	sqerr = sqlite3_prepare_v2( pSQL3,  "UPDATE  LAST_KEEPALIVE SET TIMESTAMP = ?; ", -1, &pstmt, NULL);
	if(returnOnError(LOGFD,pSQL3, "update/prepare",  sqerr,pstmt)) return;

	sqerr = sqlite3_bind_int64(pstmt, 1, msg.ts );

	sqerr = sqlite3_step( pstmt);
	if(returnOnError(LOGFD,pSQL3, "update/step",  sqerr,pstmt)) return;

	sqerr = sqlite3_finalize( pstmt);
	if(returnOnError(LOGFD,pSQL3, "update/finalize",  sqerr, pstmt)) return ;

	sqerr = sqlite3_exec( pSQL3, "COMMIT TRANSACTION", NULL, NULL, NULL );
	sqlite3_close(pSQL3);
}

/* log session close */
void p_sqldump_add_close(struct peer_t *peer, int id, struct timeval *ts)
{
	int sqerr = SQLITE_OK;
	sqlite3 * pSQL3=NULL;
	sqlite3_stmt  * pstmt=NULL;

	p_sqldump_check_file(peer,id,ts);

	sqerr = sqlite3_open_v2( peer[id].sqldbname, &pSQL3, SQLITE_OPEN_READWRITE, NULL);
	if(returnOnError(LOGFD,pSQL3, "bgpclose/open", sqerr, pstmt)) return;
	sqlite3_busy_timeout(pSQL3, 10000);
	sqerr = sqlite3_exec( pSQL3, "BEGIN TRANSACTION", NULL, NULL, NULL );

	// retain structure as much as possible from p_dump so fill this msg 
	struct dump_msg msg;
	msg.ts   = ((uint64_t)ts->tv_sec);

	sqerr = sqlite3_prepare_v2( pSQL3,  
		"INSERT INTO EVENTS (TIMESTAMP, DESCRIPTION) VALUES (?,?); ",
		-1, &pstmt, NULL);
	if(returnOnError(LOGFD,pSQL3, "addclose/insert/prepare",  sqerr, pstmt)) return;

	sqerr = sqlite3_bind_int64(pstmt,  1, msg.ts );
	sqerr = sqlite3_bind_text(pstmt, 2, "connection close", -1, NULL );

	sqerr = sqlite3_step( pstmt);
	if(returnOnError(LOGFD,pSQL3, "addclose/step",  sqerr, pstmt)) return;

	sqerr = sqlite3_finalize( pstmt);
	if(returnOnError(LOGFD,pSQL3, "addclose/finalize",  sqerr, pstmt)) return;

	sqerr = sqlite3_exec( pSQL3, "COMMIT TRANSACTION", NULL, NULL, NULL );
	sqlite3_close(pSQL3);
}

/* log session open */
void p_sqldump_add_open(struct peer_t *peer, int id, struct timeval *ts)
{
	int sqerr = SQLITE_OK;
	sqlite3 * pSQL3=NULL;
	sqlite3_stmt  * pstmt=NULL;

	p_sqldump_check_file(peer,id,ts);

	sqerr = sqlite3_open_v2( peer[id].sqldbname, &pSQL3, SQLITE_OPEN_READWRITE, NULL);
	if(returnOnError(LOGFD,pSQL3, "open/db", sqerr, pstmt)) return;
	sqlite3_busy_timeout(pSQL3, 10000);
	sqerr = sqlite3_exec( pSQL3, "BEGIN TRANSACTION", NULL, NULL, NULL );

	// retain structure as much as possible from p_dump so fill this msg 
	struct dump_msg msg;
	msg.ts   = ((uint64_t)ts->tv_sec);

	sqerr = sqlite3_prepare_v2( pSQL3,  "INSERT INTO EVENTS (TIMESTAMP, DESCRIPTION) VALUES (?,?); ", -1, &pstmt, NULL);
	if(returnOnError(LOGFD,pSQL3, "addopen/insert/prepare",  sqerr, pstmt)) return;

	sqerr = sqlite3_bind_int64(pstmt,  1, msg.ts );
	sqerr = sqlite3_bind_text(pstmt, 2, "connection open", -1 , NULL );

	sqerr = sqlite3_step( pstmt);
	if(returnOnError(LOGFD,pSQL3, "addopen/step",  sqerr, pstmt)) return;

	sqerr = sqlite3_finalize( pstmt);
	if(returnOnError(LOGFD,pSQL3, "addopen/finalize",  sqerr, pstmt)) return;

	sqerr = sqlite3_exec( pSQL3, "COMMIT TRANSACTION", NULL, NULL, NULL );
	sqlite3_close(pSQL3);
}

/* footer for each EOF */
void p_sqldump_add_footer(struct peer_t *peer, int id, struct timeval *ts)
{
	// no need //
}

/* log bgp IPv4 withdrawn msg */
void p_sqldump_add_withdrawn4(struct peer_t *peer, int id, struct timeval *ts, uint32_t prefix, uint8_t mask)
{
	int sqerr = SQLITE_OK;
	sqlite3 * pSQL3=NULL;
	sqlite3_stmt  * pstmt=NULL;

	p_sqldump_check_file(peer,id,ts);

	sqerr = sqlite3_open_v2( peer[id].sqldbname, &pSQL3, SQLITE_OPEN_READWRITE, NULL);
	if(returnOnError(LOGFD,pSQL3, "withdrawn4/open", sqerr, pstmt)) return;
	sqlite3_busy_timeout(pSQL3, 10000);
	sqerr = sqlite3_exec( pSQL3, "BEGIN TRANSACTION", NULL, NULL, NULL );

	sqerr = sqlite3_prepare_v2( pSQL3,  "DELETE FROM PREFIX_PATHS_V4 WHERE PREFIX=?; ", -1, &pstmt, NULL);
	if(returnOnError(LOGFD,pSQL3, "withdrawn4/prepare",  sqerr, pstmt)) return;

	char buf[128];
	struct in_addr addr;
	addr.s_addr = htobe32(prefix);
	sprintf(buf, "%s/%d", inet_ntoa(addr), mask);

	sqerr = sqlite3_bind_text(pstmt, 1, buf,  -1 , NULL );
	if(returnOnError(LOGFD,pSQL3, "withdrawn4/bind",  sqerr, pstmt)) return;
	sqerr = sqlite3_step( pstmt);
	if(returnOnError(LOGFD,pSQL3, "withdrawn4/step",  sqerr, pstmt)) return;
	sqerr = sqlite3_finalize( pstmt);
	if(returnOnError(LOGFD,pSQL3, "withdrawn4/finalize",  sqerr, pstmt)) return;

	sqerr = sqlite3_exec( pSQL3, "COMMIT TRANSACTION", NULL, NULL, NULL );
	sqlite3_close(pSQL3);
}

/* log bgp IPv6 withdrawn msg */
void p_sqldump_add_withdrawn6(struct peer_t *peer, int id, struct timeval *ts, uint8_t prefix[16], uint8_t mask)
{
	int sqerr = SQLITE_OK;
	sqlite3 * pSQL3=NULL;
	sqlite3_stmt  * pstmt=NULL;

	p_sqldump_check_file(peer,id,ts);

	sqerr = sqlite3_open_v2( peer[id].sqldbname, &pSQL3, SQLITE_OPEN_READWRITE, NULL);
	if(returnOnError(LOGFD,pSQL3, "withdrawn6/open", sqerr, pstmt))return;
	sqlite3_busy_timeout(pSQL3, 10000);
	sqerr = sqlite3_exec( pSQL3, "BEGIN TRANSACTION", NULL, NULL, NULL );

	sqerr = sqlite3_prepare_v2( pSQL3,  "DELETE FROM PREFIX_PATHS_V6 WHERE PREFIX=?; ", -1, &pstmt, NULL);
	if(returnOnError(LOGFD,pSQL3, "withdrawn6/prepare",  sqerr, pstmt)) return;

	char buf[128];
	inet_ntop(AF_INET6,prefix,buf,INET6_ADDRSTRLEN);

	sqerr = sqlite3_bind_text(pstmt, 1, buf,  -1 , NULL );
	if(returnOnError(LOGFD,pSQL3, "withdrawn6/bind",  sqerr, pstmt)) return;
	sqerr = sqlite3_step( pstmt);
	if(returnOnError(LOGFD,pSQL3, "withdrawn6/step",  sqerr, pstmt)) return;
	sqerr = sqlite3_finalize( pstmt);
	if(returnOnError(LOGFD,pSQL3, "withdrawn6/finalize",  sqerr, pstmt)) return;

	sqerr = sqlite3_exec( pSQL3, "COMMIT TRANSACTION", NULL, NULL, NULL );
	sqlite3_close(pSQL3);
}

/* log IPv4 bgp announce msg */
void p_sqldump_add_announce4(struct peer_t *peer, int id, struct timeval *ts,
			uint32_t prefix,      uint8_t mask,
			uint8_t origin,       uint32_t nexthop,
			void *aspath,         uint16_t aspathlen,
			void *community,      uint16_t communitylen,
			void *extcommunity4,  uint16_t extcommunitylen4,
			void *largecommunity, uint16_t largecommunitylen )
{
	int sqerr = SQLITE_OK;
	sqlite3 * pSQL3=NULL;
	sqlite3_stmt  * pstmt=NULL;

	char aspathbuf[1024], prefixbuf[128], nexthopbuf[128];
	p_sqldump_check_file(peer,id,ts);

	sqerr = sqlite3_open_v2( peer[id].sqldbname, &pSQL3, SQLITE_OPEN_READWRITE, NULL);
	if(returnOnError(LOGFD,pSQL3, "bgpclose/open", sqerr, pstmt)) return;
	sqlite3_busy_timeout(pSQL3, 10000);
	sqerr = sqlite3_exec( pSQL3, "BEGIN TRANSACTION", NULL, NULL, NULL );

	peer[id].empty = 0;

		struct dump_msg                     msg;
		struct dump_announce_aspath         opt_aspath;

		msg.type = DUMP_ANNOUNCE4;
		msg.ts   = ((uint64_t)ts->tv_sec);


		if ( aspathlen > 0 )
		{
			int i;
			for(i=0; i<aspathlen; i++)
			{
				if ( peer[id].as4 )
					opt_aspath.data[i] = htobe32(*((uint32_t*)aspath+i));
				else
					opt_aspath.data[i] = *((uint16_t*)aspath+i);
			}
		}


		// insert 
		aspathbuf[0]=0;
		int i;
		for(i=0; i<aspathlen; i++)
		{
			char b[64];
			sprintf(b, "%u", opt_aspath.data[i]);
			strcat(aspathbuf, b);
			if (i < aspathlen-1) {
				strcat(aspathbuf, " ");
			}
		}



		/* prefix  */
		struct in_addr addr;
		addr.s_addr = htobe32(prefix);
		sprintf(prefixbuf, "%s/%d", inet_ntoa(addr), mask);

		/* nexthop buf */
		addr.s_addr = htobe32(nexthop);
		sprintf(nexthopbuf, "%s", inet_ntoa(addr));




	sqerr = sqlite3_prepare_v2( pSQL3,  
		"INSERT OR REPLACE  INTO PREFIX_PATHS_V4  (PREFIX,ASPATH,COMMUNITYPATH,NEXTHOP,TIMESTAMP ) VALUES (?,?,?, ?,?); ",
		-1, &pstmt, NULL);
	if(returnOnError(LOGFD,pSQL3, "announcev4/insert/prepare",  sqerr, pstmt)) return;

	sqerr = sqlite3_bind_text(pstmt,  1, prefixbuf,    -1, NULL);
	sqerr = sqlite3_bind_text(pstmt,  2, aspathbuf,    -1, NULL);
	sqerr = sqlite3_bind_null(pstmt,  3 );
	sqerr = sqlite3_bind_text(pstmt,  4, nexthopbuf,   -1, NULL);
	sqerr = sqlite3_bind_int64(pstmt, 5, msg.ts );

	sqerr = sqlite3_step( pstmt);
	if(returnOnError(LOGFD,pSQL3, "announcev4/step",  sqerr, pstmt)) return;
	sqerr = sqlite3_finalize( pstmt);
	if(returnOnError(LOGFD,pSQL3, "announcev4/finalize",  sqerr, pstmt)) return;

	sqerr = sqlite3_exec( pSQL3, "COMMIT TRANSACTION", NULL, NULL, NULL );
	sqlite3_close(pSQL3);
}

/* log IPv6 bgp announce msg */
void p_sqldump_add_announce6(struct peer_t *peer, int id, struct timeval *ts,
			uint8_t prefix[16],   uint8_t mask,
			uint8_t origin,       uint8_t nexthop[16],
			void *aspath,         uint16_t aspathlen,
			void *community,      uint16_t communitylen,
			void *extcommunity6,  uint16_t extcommunitylen6,
			void *largecommunity, uint16_t largecommunitylen )
{
	int sqerr = SQLITE_OK;
	sqlite3 * pSQL3=NULL;
	sqlite3_stmt  * pstmt=NULL;

	char aspathbuf[1024], prefixbuf[128], nexthopbuf[128];
	p_sqldump_check_file(peer,id,ts);
	
	sqerr = sqlite3_open_v2( peer[id].sqldbname, &pSQL3, SQLITE_OPEN_READWRITE, NULL);
	if(returnOnError(LOGFD,pSQL3, "announcev6/open", sqerr,pstmt)) return;

	sqlite3_busy_timeout(pSQL3, 10000);

	sqerr = sqlite3_exec( pSQL3, "BEGIN TRANSACTION", NULL, NULL, NULL );
	if(returnOnError(LOGFD,pSQL3, "announcev6/begintrans", sqerr,pstmt)) return;

	peer[id].empty = 0;
		struct dump_msg                     msg;
		struct dump_announce_aspath         opt_aspath;

		msg.type = DUMP_ANNOUNCE6;
		msg.ts   = ((uint64_t)ts->tv_sec);

		if ( aspathlen > 0 )
		{
			int i;
			for(i=0; i<aspathlen; i++)
			{
				if ( peer[id].as4 )
					opt_aspath.data[i] = htobe32(*((uint32_t*)aspath+i));
				else
					opt_aspath.data[i] = *((uint16_t*)aspath+i);
			}
		}


		// insert 
		aspathbuf[0]=0;
		int i;
		for(i=0; i<aspathlen; i++)
		{
			char b[64];
			sprintf(b, "%u ", opt_aspath.data[i]);
			strcat(aspathbuf, b);
		}



		/* prefix  */
		char prefixv6[128];
		inet_ntop(AF_INET6,prefix,prefixv6,INET6_ADDRSTRLEN);
		sprintf(prefixbuf,"%s/%d",  prefixv6, mask);

		/* nexthop buf */
		inet_ntop(AF_INET6,nexthop,nexthopbuf,INET6_ADDRSTRLEN);


	sqerr = sqlite3_prepare_v2( pSQL3,  
		"INSERT OR REPLACE  INTO PREFIX_PATHS_V6  (PREFIX,ASPATH,COMMUNITYPATH,NEXTHOP,TIMESTAMP ) VALUES (?,?,?, ?,?); ",
		-1, &pstmt, NULL);
	if(returnOnError(LOGFD,pSQL3, "announcev6/insert/prepare",  sqerr, pstmt )) return;

	sqerr = sqlite3_bind_text(pstmt,  1, prefixbuf,    -1, NULL);
	sqerr = sqlite3_bind_text(pstmt,  2, aspathbuf,    -1, NULL);
	sqerr = sqlite3_bind_null(pstmt,  3 );
	sqerr = sqlite3_bind_text(pstmt,  4, nexthopbuf,   -1, NULL);
	sqerr = sqlite3_bind_int64(pstmt, 5, msg.ts );

	sqerr = sqlite3_step( pstmt);
	if(returnOnError(LOGFD,pSQL3, "announcev6/step",  sqerr, pstmt)) return;
	sqerr = sqlite3_finalize( pstmt);
	if(returnOnError(LOGFD,pSQL3, "announcev6/finalize",  sqerr, pstmt)) return;

	sqerr = sqlite3_exec( pSQL3, "COMMIT TRANSACTION", NULL, NULL, NULL );
	sqlite3_close(pSQL3);
}

/* check if need to reopen a new file */
void p_sqldump_check_file(struct peer_t *peer, int id, struct timeval *ts)
{
	if (strlen(peer[id].sqldbname) == 0 ) 
	{
		p_sqldump_open_file(peer,id,ts);
	}
}

/* file header */
void p_sqldump_add_header4(struct peer_t *peer, int id, struct timeval *ts)
{
}

/* file header */
void p_sqldump_add_header6(struct peer_t *peer, int id, struct timeval *ts)
{
}

/* close file */
void p_sqldump_close_file(struct peer_t *peer, int id)
{
}

