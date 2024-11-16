//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "config_file.h"

#include <cstring>
#include <sstream>
#include <string>

<<<<<<< HEAD
=======
#include "detection/detect.h"
>>>>>>> offload
#include "detection/detection_engine.h"
#include "log/messages.h"
#include "main/analyzer.h"
#include "main/policy.h"

using namespace snort;

static std::string lua_conf;
static std::string snort_conf_dir;

const char* get_snort_conf()
{ return lua_conf.c_str(); }

const char* get_snort_conf_dir()
{ return snort_conf_dir.c_str(); }

static int GetChecksumFlags(const char* args)
{
    int negative_flags = 0;
    int positive_flags = 0;
    int got_positive_flag = 0;
    int got_negative_flag = 0;
    int ret_flags = 0;

    if (args == nullptr)
        return CHECKSUM_FLAG__ALL;

    std::stringstream ss(args);
    std::string tok;

    while ( ss >> tok )
    {
        if ( tok == "all" )
        {
            positive_flags = CHECKSUM_FLAG__ALL;
            negative_flags = 0;
            got_positive_flag = 1;
        }
        else if ( tok == "none" )
        {
            positive_flags = 0;
            negative_flags = CHECKSUM_FLAG__ALL;
            got_negative_flag = 1;
        }
        else if ( tok == "ip" )
        {
            positive_flags |= CHECKSUM_FLAG__IP;
            negative_flags &= ~CHECKSUM_FLAG__IP;
            got_positive_flag = 1;
        }
        else if ( tok == "noip" )
        {
            positive_flags &= ~CHECKSUM_FLAG__IP;
            negative_flags |= CHECKSUM_FLAG__IP;
            got_negative_flag = 1;
        }
        else if ( tok == "tcp" )
        {
            positive_flags |= CHECKSUM_FLAG__TCP;
            negative_flags &= ~CHECKSUM_FLAG__TCP;
            got_positive_flag = 1;
        }
        else if ( tok == "notcp" )
        {
            positive_flags &= ~CHECKSUM_FLAG__TCP;
            negative_flags |= CHECKSUM_FLAG__TCP;
            got_negative_flag = 1;
        }
        else if ( tok == "udp" )
        {
            positive_flags |= CHECKSUM_FLAG__UDP;
            negative_flags &= ~CHECKSUM_FLAG__UDP;
            got_positive_flag = 1;
        }
        else if ( tok == "noudp" )
        {
            positive_flags &= ~CHECKSUM_FLAG__UDP;
            negative_flags |= CHECKSUM_FLAG__UDP;
            got_negative_flag = 1;
        }
        else if ( tok == "icmp" )
        {
            positive_flags |= CHECKSUM_FLAG__ICMP;
            negative_flags &= ~CHECKSUM_FLAG__ICMP;
            got_positive_flag = 1;
        }
        else if ( tok == "noicmp" )
        {
            positive_flags &= ~CHECKSUM_FLAG__ICMP;
            negative_flags |= CHECKSUM_FLAG__ICMP;
            got_negative_flag = 1;
        }
        else
        {
            ParseError("unknown command line checksum option: %s.", tok.c_str());
            return ret_flags;
        }
    }

    /* Invert the negative flags with all checksums */
    negative_flags ^= CHECKSUM_FLAG__ALL;
    negative_flags &= CHECKSUM_FLAG__ALL;

    if (got_positive_flag && got_negative_flag)
    {
        /* If we got both positive and negative flags just take the
         * combination of the two */
        ret_flags = positive_flags & negative_flags;
    }
    else if (got_positive_flag)
    {
        /* If we got a positive flag assume the user wants checksums
         * to be cleared */
        ret_flags = positive_flags;
    }
    else  /* got a negative flag */
    {
        /* If we got a negative flag assume the user thinks all
         * checksums are on */
        ret_flags = negative_flags;
    }

    return ret_flags;
}

void ConfigChecksumDrop(const char* args)
{
    NetworkPolicy* policy = get_network_policy();
    policy->checksum_drop = GetChecksumFlags(args);
}

void ConfigChecksumMode(const char* args)
{
    NetworkPolicy* policy = get_network_policy();
    policy->checksum_eval = GetChecksumFlags(args);
}

<<<<<<< HEAD
void config_conf(const char* val)
{
    lua_conf = val;
    SetSnortConfDir(lua_conf.c_str());
    Analyzer::set_main_hook(DetectionEngine::inspect);
=======
void ConfigChrootDir(SnortConfig* sc, const char* args)
{
    if ( !args || !sc )
        return;

    sc->chroot_dir = args;
}

void ConfigCreatePidFile(SnortConfig* sc, const char*)
{
    sc->run_flags |= RUN_FLAG__CREATE_PID_FILE;
}

void ConfigDaemon(SnortConfig* sc, const char*)
{
    DebugMessage(DEBUG_INIT, "Daemon mode flag set\n");
    sc->run_flags |= RUN_FLAG__DAEMON;
}

void ConfigDecodeDataLink(SnortConfig* sc, const char*)
{
    DebugMessage(DEBUG_INIT, "Decode DLL set\n");
    sc->output_flags |= OUTPUT_FLAG__SHOW_DATA_LINK;
}

void ConfigDumpCharsOnly(SnortConfig* sc, const char*)
{
    /* dump the application layer as text only */
    DebugMessage(DEBUG_INIT, "Character payload dump set\n");
    sc->output_flags |= OUTPUT_FLAG__CHAR_DATA;
}

void ConfigDumpPayload(SnortConfig* sc, const char*)
{
    /* dump the application layer */
    DebugMessage(DEBUG_INIT, "Payload dump set\n");
    sc->output_flags |= OUTPUT_FLAG__APP_DATA;
}

void ConfigDumpPayloadVerbose(SnortConfig* sc, const char*)
{
    DebugMessage(DEBUG_INIT, "Verbose packet bytecode dumps enabled\n");
    sc->output_flags |= OUTPUT_FLAG__VERBOSE_DUMP;
}

void ConfigDstMac(SnortConfig* sc, const char* s)
{
    eth_addr_t dst;

    if ( eth_pton(s, &dst) < 0 )
    {
        ParseError("format check failed: %s,  Use format like 12:34:56:78:90:1a", s);
        return;
    }
    sc->eth_dst = (uint8_t*)snort_calloc(sizeof(dst.data));
    memcpy(sc->eth_dst, dst.data, sizeof(dst.data));
}

void ConfigLogDir(SnortConfig* sc, const char* args)
{
    if ( !args || !sc )
        return;

    sc->log_dir = args;
}

void ConfigDirtyPig(SnortConfig* sc, const char*)
{
    if ( sc )
        sc->dirty_pig = 1;
}

void ConfigObfuscate(SnortConfig* sc, const char*)
{
    sc->output_flags |= OUTPUT_FLAG__OBFUSCATE;
}

void ConfigNoLoggingTimestamps(SnortConfig* sc, const char*)
{
    sc->output_flags |= OUTPUT_FLAG__NO_TIMESTAMP;
}

void ConfigObfuscationMask(SnortConfig* sc, const char* args)
{
    if ( !args )
        return;

    DebugFormat(DEBUG_INIT, "Got obfus data: %s\n", args);

    sc->output_flags |= OUTPUT_FLAG__OBFUSCATE;

    sc->obfuscation_net.set(args);
}

void ConfigQuiet(SnortConfig* sc, const char*)
{
    sc->logging_flags |= LOGGING_FLAG__QUIET;
}

void ConfigSetGid(SnortConfig* sc, const char* args)
{
    size_t i;
    char* endptr;

    if ( !args )
        return;

    for (i = 0; i < strlen(args); i++)
    {
        /* If we get something other than a digit, assume it's
         * a group name */
        if (!isdigit((int)args[i]))
        {
            struct group* gr = getgrnam(args);  // main thread only

            if (gr == NULL)
            {
                ParseError("group '%s' unknown.", args);
                return;
            }

            sc->group_id = gr->gr_gid;
            break;
        }
    }

    /* It's all digits.  Assume it's a group id */
    if (i == strlen(args))
    {
        sc->group_id = SnortStrtol(args, &endptr, 10);
        if ((errno == ERANGE) || (*endptr != '\0') ||
            (sc->group_id < 0))
        {
            ParseError("group id '%s' out of range.", args);
        }
    }
}

void ConfigSetUid(SnortConfig* sc, const char* args)
{
    size_t i;
    char* endptr;

    if ( !args )
        return;

    for (i = 0; i < strlen(args); i++)
    {
        /* If we get something other than a digit, assume it's
         * a user name */
        if (!isdigit((int)args[i]))
        {
            struct passwd* pw = getpwnam(args);  // main thread only

            if (pw == NULL)
            {
                ParseError("user '%s' unknown.", args);
                return;
            }

            sc->user_id = (int)pw->pw_uid;

            /* Why would someone want to run as another user
             * but still as root group? */
            if (sc->group_id == -1)
                sc->group_id = (int)pw->pw_gid;

            break;
        }
    }

    /* It's all digits.  Assume it's a user id */
    if (i == strlen(args))
    {
        sc->user_id = SnortStrtol(args, &endptr, 10);
        if ((errno == ERANGE) || (*endptr != '\0'))
        {
            ParseError("user id '%s' out of range.", args);
            return;
        }

        /* Set group id to user's default group if not
         * already set */
        if (sc->group_id == -1)
        {
            struct passwd* pw = getpwuid((uid_t)sc->user_id);  // main thread only

            if (pw == NULL)
            {
                ParseError("user '%s' unknown.", args);
                return;
            }

            sc->group_id = (int)pw->pw_gid;
        }
    }

    DebugFormat(DEBUG_INIT, "UserID: %d GroupID: %d.\n",
        sc->user_id, sc->group_id);
}

void ConfigShowYear(SnortConfig* sc, const char*)
{
    sc->output_flags |= OUTPUT_FLAG__INCLUDE_YEAR;
    DebugMessage(DEBUG_INIT, "Enabled year in timestamp\n");
}

void ConfigTreatDropAsAlert(SnortConfig* sc, const char*)
{
    sc->run_flags |= RUN_FLAG__TREAT_DROP_AS_ALERT;
}

void ConfigTreatDropAsIgnore(SnortConfig* sc, const char*)
{
    sc->run_flags |= RUN_FLAG__TREAT_DROP_AS_IGNORE;
}

void ConfigProcessAllEvents(SnortConfig* sc, const char*)
{
    sc->run_flags |= RUN_FLAG__PROCESS_ALL_EVENTS;
}

#ifdef ACCESSPERMS
# define FILEACCESSBITS ACCESSPERMS
#else
# ifdef S_IAMB
#  define FILEACCESSBITS S_IAMB
# else
#  define FILEACCESSBITS 0x1FF
# endif
#endif

void ConfigUmask(SnortConfig* sc, const char* args)
{
    char* endptr;
    long mask;

    mask = SnortStrtol(args, &endptr, 0);

    if ((errno == ERANGE) || (*endptr != '\0') ||
        (mask < 0) || (mask & ~FILEACCESSBITS))
    {
        ParseError("bad umask: %s", args);
    }
    sc->file_mask = (mode_t)mask;
}

void ConfigUtc(SnortConfig* sc, const char*)
{
    sc->output_flags |= OUTPUT_FLAG__USE_UTC;
}

void ConfigVerbose(SnortConfig* sc, const char*)
{
    sc->logging_flags |= LOGGING_FLAG__VERBOSE;
    DebugMessage(DEBUG_INIT, "Verbose Flag active\n");
}

void ConfigTunnelVerdicts(SnortConfig* sc, const char* args)
{
    char* tmp, * tok;

    tmp = snort_strdup(args);
    char* lasts = { 0 };
    tok = strtok_r(tmp, " ,", &lasts);

    while ( tok )
    {
        if ( !strcasecmp(tok, "gtp") )
            sc->tunnel_mask |= TUNNEL_GTP;

        else if ( !strcasecmp(tok, "teredo") )
            sc->tunnel_mask |= TUNNEL_TEREDO;

        else if ( !strcasecmp(tok, "6in4") )
            sc->tunnel_mask |= TUNNEL_6IN4;

        else if ( !strcasecmp(tok, "4in6") )
            sc->tunnel_mask |= TUNNEL_4IN6;

        else
        {
            ParseError("unknown tunnel bypass protocol");
            return;
        }

        tok = strtok_r(NULL, " ,", &lasts);
    }
    snort_free(tmp);
}

void ConfigPluginPath(SnortConfig* sc, const char* args)
{
    if ( sc && args )
        sc->plugin_path = args;
}

void ConfigScriptPaths(SnortConfig* sc, const char* args)
{
    if ( sc && args )
        sc->script_paths.push_back(args);
}

void config_syslog(SnortConfig* sc, const char*)
{
    static bool syslog_configured = false;

    if (syslog_configured)
        return;

    openlog("snort", LOG_PID | LOG_CONS, LOG_DAEMON);

    sc->logging_flags |= LOGGING_FLAG__SYSLOG;
    syslog_configured = true;
}

void config_daemon(SnortConfig* sc, const char* val)
{
    static bool daemon_configured = false;

    if (daemon_configured)
        return;

    ConfigDaemon(sc, val);
    daemon_configured = true;
}

void config_alert_mode(SnortConfig* sc, const char* val)
{
    if (strcasecmp(val, ALERT_NONE) == 0)
        EventManager::enable_alerts(false);

    else if ( !strcasecmp(val, ALERT_CMG) or !strcasecmp(val, ALERT_JH) or
        !strcasecmp(val, ALERT_DJR) )
    {
        sc->output = OUTPUT_FAST;
        sc->output_flags |= OUTPUT_FLAG__SHOW_DATA_LINK;
        sc->output_flags |= OUTPUT_FLAG__APP_DATA;
    }
    else if ( !strcasecmp(val, ALERT_U2) or !strcasecmp(val, ALERT_AJK) )
        sc->output = OUTPUT_U2;

    else
        sc->output = val;

    sc->output_flags |= OUTPUT_FLAG__ALERTS;
    Snort::set_main_hook(DetectionEngine::inspect);
}

void config_log_mode(SnortConfig* sc, const char* val)
{
    if (strcasecmp(val, LOG_NONE) == 0)
    {
        Snort::set_main_hook(snort_ignore);
        EventManager::enable_logs(false);
    }
    else
    {
        if ( !strcmp(val, LOG_DUMP) )
            val = LOG_CODECS;
        sc->output = val;
        Snort::set_main_hook(snort_log);
    }
}

void config_conf(SnortConfig*, const char* val)
{
    lua_conf = val;
    SetSnortConfDir(lua_conf.c_str());
    Snort::set_main_hook(DetectionEngine::inspect);
>>>>>>> offload
}

void SetSnortConfDir(const char* file)
{
    /* extract the config directory from the config filename */
    if ( file )
    {
        const char* path_sep = strrchr(file, '/');

        /* is there a directory separator in the filename */
        if (path_sep != nullptr)
        {
            path_sep++;  /* include path separator */
            snort_conf_dir.assign(file, path_sep - file);
        }
        else
        {
            snort_conf_dir = "./";
        }
    }
}

