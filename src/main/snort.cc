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

#include "snort.h"

#include <daq.h>
#include <sys/stat.h>
#include <syslog.h>

#include "actions/ips_actions.h"
#include "codecs/codec_api.h"
#include "connectors/connectors.h"
<<<<<<< HEAD
#include "detection/fp_config.h"
=======
#include "decompress/file_decomp.h"
#include "detection/context_switcher.h"
#include "detection/detect.h"
#include "detection/detection_engine.h"
#include "detection/detection_util.h"
#include "detection/fp_config.h"
#include "detection/fp_detect.h"
#include "detection/ips_context.h"
#include "detection/tag.h"
>>>>>>> offload
#include "file_api/file_service.h"
#include "filters/detection_filter.h"
#include "filters/rate_filter.h"
#include "filters/sfrf.h"
#include "filters/sfthreshold.h"
#include "flow/ha.h"
#include "framework/endianness.h"
#include "framework/mpse.h"
#include "host_tracker/host_cache.h"
#include "host_tracker/host_cache_segmented.h"
#include "host_tracker/host_tracker_module.h"
#include "ips_options/ips_options.h"
#include "log/log.h"
#include "log/log_errors.h"
#include "loggers/loggers.h"
#include "main.h"
#include "main/process.h"
#include "main/shell.h"
#include "managers/codec_manager.h"
#include "managers/inspector_manager.h"
#include "managers/ips_manager.h"
#include "managers/event_manager.h"
#include "managers/module_manager.h"
#include "managers/mpse_manager.h"
#include "managers/plugin_manager.h"
#include "managers/policy_selector_manager.h"
#include "managers/script_manager.h"
#include "memory/memory_cap.h"
#include "network_inspectors/network_inspectors.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq.h"
#include "packet_io/trough.h"
#include "parser/cmd_line.h"
#include "parser/parser.h"
#include "policy_selectors/policy_selectors.h"
#include "profiler/profiler.h"
#include "search_engines/search_engines.h"
#include "service_inspectors/service_inspectors.h"
#include "side_channel/side_channel.h"
#include "stream/stream_inspectors.h"
#include "stream/stream.h"
#include "target_based/host_attributes.h"
#include "time/periodic.h"
#include "trace/trace_api.h"
#include "trace/trace_config.h"
#include "trace/trace_logger.h"
#include "utils/stats.h"
#include "utils/util.h"

#ifdef SHELL
#include "control/control_mgmt.h"
#include "ac_shell_cmd.h"
#endif

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

#include "snort_config.h"
#include "thread_config.h"

using namespace snort;
using namespace std;

static SnortConfig* snort_cmd_line_conf = nullptr;
static pid_t snort_main_thread_pid = 0;

<<<<<<< HEAD
=======
// non-local for easy access from core
static THREAD_LOCAL DAQ_PktHdr_t s_pkth;
static THREAD_LOCAL uint8_t s_data[65536];
static THREAD_LOCAL Packet* s_packet = nullptr;
static THREAD_LOCAL ContextSwitcher* s_switcher = nullptr;

ContextSwitcher* Snort::get_switcher()
{ return s_switcher; }

//-------------------------------------------------------------------------
// perf stats
// FIXIT-M move these to appropriate modules
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats totalPerfStats;
static THREAD_LOCAL ProfileStats metaPerfStats;

static ProfileStats* get_profile(const char* key)
{
    if ( !strcmp(key, "detect") )
        return &detectPerfStats;

    if ( !strcmp(key, "mpse") )
        return &mpsePerfStats;

    if ( !strcmp(key, "rebuilt_packet") )
        return &rebuiltPacketPerfStats;

    if ( !strcmp(key, "rule_eval") )
        return &rulePerfStats;

    if ( !strcmp(key, "rtn_eval") )
        return &ruleRTNEvalPerfStats;

    if ( !strcmp(key, "rule_tree_eval") )
        return &ruleOTNEvalPerfStats;

    if ( !strcmp(key, "nfp_rule_tree_eval") )
        return &ruleNFPEvalPerfStats;

    if ( !strcmp(key, "decode") )
        return &decodePerfStats;

    if ( !strcmp(key, "eventq") )
        return &eventqPerfStats;

    if ( !strcmp(key, "total") )
        return &totalPerfStats;

    if ( !strcmp(key, "daq_meta") )
        return &metaPerfStats;

    return nullptr;
}

static void register_profiles()
{
    Profiler::register_module("detect", nullptr, get_profile);
    Profiler::register_module("mpse", "detect", get_profile);
    Profiler::register_module("rebuilt_packet", "detect", get_profile);
    Profiler::register_module("rule_eval", "detect", get_profile);
    Profiler::register_module("rtn_eval", "rule_eval", get_profile);
    Profiler::register_module("rule_tree_eval", "rule_eval", get_profile);
    Profiler::register_module("nfp_rule_tree_eval", "rule_eval", get_profile);
    Profiler::register_module("decode", nullptr, get_profile);
    Profiler::register_module("eventq", nullptr, get_profile);
    Profiler::register_module("total", nullptr, get_profile);
    Profiler::register_module("daq_meta", nullptr, get_profile);
}

//-------------------------------------------------------------------------
// helpers
//-------------------------------------------------------------------------

static void pass_pkts(Packet*) { }
static MainHook_f main_hook = pass_pkts;

static void set_policy(Packet* p)  // FIXIT-M delete this?
{
    set_default_policy();
    p->user_policy_id = get_ips_policy()->user_policy_id;
}

static void show_source(const char* pcap)
{
    if ( !SnortConfig::pcap_show() )
        return;

    if ( !strcmp(pcap, "-") )
        pcap = "stdin";

    static bool first = true;
    if ( first )
        first = false;
    else
        fprintf(stdout, "%s", "\n");

    fprintf(stdout, "Reading network traffic from \"%s\" with snaplen = %u\n",
        pcap, SFDAQ::get_snap_len());
}

>>>>>>> offload
//-------------------------------------------------------------------------
// initialization
//-------------------------------------------------------------------------

void Snort::init(int argc, char** argv)
{
    init_signals();
    ThreadConfig::init();

#if defined(NOCOREFILE)
    SetNoCores();
#else
    StoreSnortInfoStrings();
#endif

    InitProtoNames();
    DataBus::init();

    load_actions();
    load_codecs();
    load_connectors();
    load_ips_options();
    load_loggers();
    load_search_engines();
    load_policy_selectors();
    load_stream_inspectors();
    load_network_inspectors();
    load_service_inspectors();

    snort_cmd_line_conf = parse_cmd_line(argc, argv);
    SnortConfig::set_conf(snort_cmd_line_conf);

    LogMessage("--------------------------------------------------\n");
#ifdef BUILD
    LogMessage("%s  Snort++ %s-%s\n", get_prompt(), VERSION, BUILD);
#else
    LogMessage("%s  Snort++ %s\n", get_prompt(), VERSION);
#endif
    LogMessage("--------------------------------------------------\n");

    SideChannelManager::pre_config_init();

    ScriptManager::load_scripts(snort_cmd_line_conf->script_paths);
    PluginManager::load_plugins(snort_cmd_line_conf->plugin_path);

    /* load_plugins() must be called before init() so that
    TraceModule can properly generate its Parameter table */
    ModuleManager::init();
    ModuleManager::load_params();

    FileService::init();

    parser_init();
    SnortConfig* sc = ParseSnortConf(snort_cmd_line_conf);

    /* Set the global snort_conf that will be used during run time */
    SnortConfig::set_conf(sc);

    if (!sc->policy_map->setup_network_policies())
        ParseError("Network policy user ids must be unique\n");

    // This call must be immediately after "SnortConfig::set_conf(sc)"
    // since the first trace call may happen somewhere after this point
    TraceApi::thread_init(sc->trace_config);

    PluginManager::load_so_plugins(sc);

    if ( SnortConfig::log_show_plugins() )
    {
        ModuleManager::dump_modules();
        PluginManager::dump_plugins();
    }
    CodecManager::instantiate();

    if ( !sc->output.empty() )
        EventManager::instantiate(sc->output.c_str(), sc);

    HighAvailabilityManager::configure(sc->ha_config);
    memory::MemoryCap::init(sc->thread_config->get_instance_max());

    ModuleManager::init_stats();
    ModuleManager::reset_stats(sc);

    if (sc->alert_before_pass())
        sc->rule_order = IpsAction::get_default_priorities(true);

    sc->setup();

    if ( !sc->attribute_hosts_file.empty() )
    {
        if ( !HostAttributesManager::load_hosts_file(sc, sc->attribute_hosts_file.c_str()) )
            ParseError("host attributes file failed to load\n");
    }
    HostAttributesManager::activate(sc);

    if ( SnortConfig::log_verbose() )
        PolicySelectorManager::print_config(sc);

    // Must be after CodecManager::instantiate()
    if ( !InspectorManager::configure(sc) )
        ParseError("can't initialize inspectors");
    else if ( SnortConfig::log_verbose() )
        InspectorManager::print_config(sc);

    InspectorManager::global_init();
    InspectorManager::prepare_inspectors(sc);
    InspectorManager::prepare_controls(sc);

    // Must be after InspectorManager::configure()
    FileService::post_init();

    if (sc->file_mask != 0)
        umask(sc->file_mask);
    else
        umask(077);    /* set default to be sane */

    /* Need to do this after dynamic detection stuff is initialized, too */
    IpsManager::global_init(sc);
    PacketManager::global_init(sc->num_layers);

    sc->post_setup();
    sc->update_reload_id();

    detection_filter_init(sc->detection_filter_config);

    const MpseApi* search_api = sc->fast_pattern_config->get_search_api();
    const MpseApi* offload_search_api = sc->fast_pattern_config->get_offload_search_api();

    if ( search_api )
        MpseManager::activate_search_engine(search_api, sc);

    if ( offload_search_api and offload_search_api != search_api )
        MpseManager::activate_search_engine(offload_search_api, sc);

    /* Finish up the pcap list and put in the queues */
    Trough::setup();

    // FIXIT-L refactor stuff done here and in snort_config.cc::VerifyReload()
    if ( sc->bpf_filter.empty() && !sc->bpf_file.empty() )
        sc->bpf_filter = read_infile("bpf_file", sc->bpf_file.c_str());

    if ( !sc->bpf_filter.empty() )
        LogMessage("Snort BPF option: %s\n", sc->bpf_filter.c_str());

    parser_term(sc);

    LogMessage("%s\n", LOG_DIV);

    SFDAQ::init(sc->daq_config, ThreadConfig::get_instance_max());
}

// this function should only include initialization that must be done as a
// non-root user such as creating log files.  other initialization stuff should
// be in the main initialization function since, depending on platform and
// configuration, this may be running in a background thread while passing
// packets in a fail open mode in the main thread.  we don't want big delays
// here to cause excess latency or dropped packets in that thread which may
// be the case if all threads are pinned to a single cpu/core.
//
// clarification: once snort opens/starts the DAQ, packets are queued for snort
// and must be disposed of quickly or the queue will overflow and packets will
// be dropped so the fail open thread does the remaining initialization while
// the main thread passes packets.  prior to opening and starting the DAQ,
// packet passing is done by the driver/hardware.  the goal then is to put as
// much initialization stuff in Snort::init() as possible and to restrict this
// function to those things that depend on DAQ startup or non-root user/group.

bool Snort::drop_privileges()
{
    SnortConfig* sc = SnortConfig::get_main_conf();

    // Enter the chroot jail if necessary.
    if (!sc->chroot_dir.empty() && !EnterChroot(sc->chroot_dir, sc->log_dir))
        return false;

    // Drop privileges if requested.
    if (sc->get_uid() != -1 || sc->get_gid() != -1)
    {
        if (!SFDAQ::can_run_unprivileged())
        {
            ParseError("Cannot drop privileges - "
                "at least one of the configured DAQ modules does not support unprivileged operation.\n");
            return false;
        }
        if (!SetUidGid(sc->get_uid(), sc->get_gid()))
            return false;
    }

    privileges_dropped = true;
    return true;
}

void Snort::do_pidfile()
{
    static bool pid_file_created = false;

    if (SnortConfig::get_conf()->create_pid_file() && !pid_file_created)
    {
        CreatePidFile(snort_main_thread_pid);
        pid_file_created = true;
    }
}

//-------------------------------------------------------------------------
// termination
//-------------------------------------------------------------------------

void Snort::term()
{
    /* This function can be called more than once.  For example,
     * once from the SIGINT signal handler, and once recursively
     * as a result of calling pcap_close() below.  We only need
     * to perform the cleanup once, however.  So the static
     * variable already_exiting will act as a flag to prevent
     * double-freeing any memory.  Not guaranteed to be
     * thread-safe, but it will prevent the simple cases.
     */
    if ( already_exiting )
        return;
    already_exiting = true;

    const SnortConfig* sc = SnortConfig::get_conf();

    IpsManager::global_term(sc);
    HostAttributesManager::term();

    Trough::cleanup();
    ClosePidFile();

    /* remove pid file */
    if ( !sc->pid_filename.empty() )
    {
        int ret = unlink(sc->pid_filename.c_str());

        if (ret != 0)
        {
            ErrorMessage("Could not remove pid file %s: %s\n",
                sc->pid_filename.c_str(), get_error(errno));
        }
    }

    //MpseManager::print_search_engine_stats();

    Periodic::unregister_all();

    LogMessage("%s  Snort exiting\n", get_prompt());

    // This call must be before SnortConfig cleanup
    // since the "TraceApi::thread_term()" uses SnortConfig
    TraceApi::thread_term();

    SnortConfig::set_conf(nullptr);

    /* free allocated memory */
    if (sc != snort_cmd_line_conf)
        delete sc;

    delete snort_cmd_line_conf;
    snort_cmd_line_conf = nullptr;

    CleanupProtoNames();
    HighAvailabilityManager::term();
    SideChannelManager::term();
    ModuleManager::term();
    host_cache.term();
    PluginManager::release_plugins();
    ScriptManager::release_scripts();
    memory::MemoryCap::term();
    detection_filter_term();

    term_signals();
}

void Snort::clean_exit(int)
{
    term();
    closelog();
}

//-------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

bool Snort::reloading = false;
bool Snort::privileges_dropped = false;
bool Snort::already_exiting = false;

bool Snort::is_reloading()
{ return reloading; }

bool Snort::has_dropped_privileges()
{ return privileges_dropped; }

unsigned Snort::get_process_id()
{
    const SnortConfig* sc = SnortConfig::get_conf();
    if (!sc->id_offset)
        return 1;
    else
        return sc->id_offset / ThreadConfig::get_instance_max() + 1;
}

void Snort::setup(int argc, char* argv[])
{
    set_main_thread();

    // must be done before any other files are opened because we
    // will try to grab file descriptor 3 (if --enable-stdlog)
    OpenLogger();

    init(argc, argv);
    const SnortConfig* sc = SnortConfig::get_conf();

    if ( sc->daemon_mode() )
        daemonize();

    // this must follow daemonization
    snort_main_thread_pid = gettid();

    /* Change groups */
    InitGroups(sc->get_uid(), sc->get_gid());

    set_quick_exit(false);

    memory::MemoryCap::start(*sc->memory, Stream::prune_flows);
    memory::MemoryCap::print(SnortConfig::log_verbose(), true);

    host_cache.init();
    ((HostTrackerModule*)ModuleManager::get_module(HOST_TRACKER_NAME))->init_data();
    host_cache.print_config();

    TimeStart();
}

void Snort::cleanup()
{
    TimeStop();

    SFDAQ::term();
    FileService::close();
    memory::MemoryCap::stop();

    if ( !SnortConfig::get_conf()->test_mode() )  // FIXIT-M ideally the check is in one place
        PrintStatistics();

    CloseLogger();
    ThreadConfig::term();
    clean_exit(0);
}

void Snort::reload_failure_cleanup(SnortConfig* sc)
{
    parser_term(sc);
    delete sc;
    set_default_policy(SnortConfig::get_conf());
    reloading = false;
}

// FIXIT-M refactor this so startup and reload call the same core function to
// instantiate things that can be reloaded
SnortConfig* Snort::get_reload_config(const char* fname, const char* plugin_path,
    const SnortConfig* old)
{
    reloading = true;
    ModuleManager::reset_errors();
    reset_parse_errors();
    trim_heap();

    parser_init();
    SnortConfig* sc = ParseSnortConf(snort_cmd_line_conf, fname);

    if ( get_parse_errors() || ModuleManager::get_errors() || !sc->verify() )
    {
        reload_failure_cleanup(sc);
        return nullptr;
    }

    PluginManager::reload_so_plugins(plugin_path, sc);
    sc->setup();

#ifdef SHELL
    ControlMgmt::reconfigure_controls();
#endif

    if ( get_parse_errors() or !InspectorManager::configure(sc) )
    {
        reload_failure_cleanup(sc);
        return nullptr;
    }

    InspectorManager::reconcile_inspectors(old, sc);
    InspectorManager::prepare_inspectors(sc);
    InspectorManager::prepare_controls(sc);

    FileService::verify_reload(sc);
    if ( get_reload_errors() )
    {
        reload_failure_cleanup(sc);
        return nullptr;
    }

    if ( SnortConfig::log_verbose() )
    {
        PolicySelectorManager::print_config(sc);
        InspectorManager::print_config(sc);
    }

    // FIXIT-L is this still needed?
    /* Transfer any user defined rule type outputs to the new rule list */
    {
        RuleListNode* cur = SnortConfig::get_conf()->rule_lists;

        for (; cur != nullptr; cur = cur->next)
        {
            RuleListNode* rnew = sc->rule_lists;

            for (; rnew != nullptr; rnew = rnew->next)
            {
                if (strcasecmp(cur->name, rnew->name) == 0)
                {
                    EventManager::copy_outputs(
                        rnew->RuleList->AlertList, cur->RuleList->AlertList);

                    EventManager::copy_outputs(
                        rnew->RuleList->LogList, cur->RuleList->LogList);
                    break;
                }
            }
        }
    }

    sc->post_setup();

    if ( sc->fast_pattern_config->get_search_api() !=
        SnortConfig::get_conf()->fast_pattern_config->get_search_api() )
    {
        MpseManager::activate_search_engine(sc->fast_pattern_config->get_search_api(), sc);
    }

    InspectorManager::update_policy(sc);

    if ( !sc->attribute_hosts_file.empty() )
    {
        if ( !HostAttributesManager::load_hosts_file(sc, sc->attribute_hosts_file.c_str()) )
            LogMessage("== WARNING: host attributes file failed to load\n");
    }
    HostAttributesManager::activate(sc);

    reloading = false;
    parser_term(sc);

    return sc;
}

SnortConfig* Snort::get_updated_policy(
    SnortConfig* other_conf, const char* fname, const char* iname)
{
    reloading = true;
    reset_parse_errors();

    SnortConfig* sc = new SnortConfig(other_conf, iname);
    sc->global_dbus->clone(*other_conf->global_dbus, iname);

    if ( fname )
    {
        bool uninitialized_trace = !other_conf->trace_config or
            !other_conf->trace_config->initialized;

        Shell sh = Shell(fname);
        sh.configure(sc, true);

        if ( uninitialized_trace )
        {
<<<<<<< HEAD
            LogMessage("== WARNING: Trace module was not configured during "
                "initial startup. Ignoring the new trace configuration.\n");
            sc->trace_config->clear();
=======
            s_pkth = *(s_packet->pkth);

            if ( s_packet->pkt )
            {
                memcpy(s_data, s_packet->pkt, 0xFFFF & s_packet->pkth->caplen);
                s_packet->pkt = s_data;
            }
        }
    }
}

void Snort::thread_idle()
{
    Stream::timeout_flows(time(nullptr));
    perf_monitor_idle_process();
    aux_counts.idle++;
    HighAvailabilityManager::process_receive();
}

void Snort::thread_rotate()
{
    SetRotatePerfFileFlag();
}

/*
 * Perform all packet thread initialization actions that need to be taken with escalated privileges
 * prior to starting the DAQ module.
 */
bool Snort::thread_init_privileged(const char* intf)
{
    show_source(intf);

    snort_conf->thread_config->implement_thread_affinity(STHREAD_TYPE_PACKET, get_instance_id());

    // FIXIT-M the start-up sequence is a little off due to dropping privs
    SFDAQInstance *daq_instance = new SFDAQInstance(intf);
    SFDAQ::set_local_instance(daq_instance);
    if (!daq_instance->configure(snort_conf))
        return false;

    return true;
}

/*
 * Perform all packet thread initialization actions that can be taken with dropped privileges
 * and/or must be called after the DAQ module has been started.
 */
void Snort::thread_init_unprivileged()
{
    // using dummy values until further integration
    const unsigned max_contexts = 20;

    s_switcher = new ContextSwitcher(max_contexts);

    for ( unsigned i = 0; i < max_contexts; ++i )
        s_switcher->push(new IpsContext);

    CodecManager::thread_init(snort_conf);

    // this depends on instantiated daq capabilities
    // so it is done here instead of init()
    Active::init(snort_conf);

    InitTag();
    EventTrace_Init();
    detection_filter_init(snort_conf->detection_filter_config);
    DetectionEngine::thread_init();

    EventManager::open_outputs();
    IpsManager::setup_options();
    ActionManager::thread_init(snort_conf);
    FileService::thread_init();
    SideChannelManager::thread_init();
    HighAvailabilityManager::thread_init(); // must be before InspectorManager::thread_init();
    InspectorManager::thread_init(snort_conf);

    // in case there are HA messages waiting, process them first
    HighAvailabilityManager::process_receive();
}

void Snort::thread_term()
{
    HighAvailabilityManager::thread_term_beginning();

    if ( !snort_conf->dirty_pig )
        Stream::purge_flows();

    DetectionEngine::idle();
    InspectorManager::thread_stop(snort_conf);
    ModuleManager::accumulate(snort_conf);
    InspectorManager::thread_term(snort_conf);
    ActionManager::thread_term(snort_conf);

    IpsManager::clear_options();
    EventManager::close_outputs();
    CodecManager::thread_term();
    HighAvailabilityManager::thread_term();
    SideChannelManager::thread_term();

    s_packet = nullptr;

    SFDAQInstance *daq_instance = SFDAQ::get_local_instance();
    if ( daq_instance->was_started() )
        daq_instance->stop();
    SFDAQ::set_local_instance(nullptr);
    delete daq_instance;

    PacketLatency::tterm();
    RuleLatency::tterm();

    Profiler::consolidate_stats();

    DetectionEngine::thread_term();
    detection_filter_term();
    EventTrace_Term();
    CleanupTag();
    FileService::thread_term();

    Active::term();
    delete s_switcher;
}

void Snort::inspect(Packet* p)
{
    // Need to include this b/c call is outside the detect tree
    Profile detect_profile(detectPerfStats);
    Profile rebuilt_profile(rebuiltPacketPerfStats);

    DetectionEngine de;
    main_hook(p);

    if ( DetectionEngine::offloaded(p) )
        return;

    clear_file_data();  // FIXIT-H get rid of this
}

DAQ_Verdict Snort::process_packet(
    Packet* p, const DAQ_PktHdr_t* pkthdr, const uint8_t* pkt, bool is_frag)
{
    PacketManager::decode(p, pkthdr, pkt);
    assert(p->pkth && p->pkt);

    if (is_frag)
    {
        p->packet_flags |= (PKT_PSEUDO | PKT_REBUILT_FRAG);
        p->pseudo_type = PSEUDO_PKT_IP;
    }

    set_policy(p);  // FIXIT-M should not need this here

    if ( !(p->packet_flags & PKT_IGNORE) )
    {
        clear_file_data();
        main_hook(p);
    }

    // process flow verdicts here
    if ( Active::session_was_blocked() )
    {
        if ( !Active::can_block() )
            return DAQ_VERDICT_PASS;

        if ( Active::get_tunnel_bypass() )
        {
            aux_counts.internal_blacklist++;
            return DAQ_VERDICT_PASS;
>>>>>>> offload
        }

        if ( ModuleManager::get_errors() || !sc->verify() )
        {
            sc->cloned = true;
            InspectorManager::update_policy(other_conf);
            delete sc;
            set_default_policy(other_conf);
            reloading = false;
            return nullptr;
        }
    }

    if ( iname )
    {
        if ( !InspectorManager::delete_inspector(sc, iname) )
        {
            sc->cloned = true;
            InspectorManager::update_policy(other_conf);
            delete sc;
            set_default_policy(other_conf);
            reloading = false;
            return nullptr;
        }
    }

    if ( !InspectorManager::configure(sc, true) )
    {
        sc->cloned = true;
        InspectorManager::update_policy(other_conf);
        delete sc;
        set_default_policy(other_conf);
        reloading = false;
        return nullptr;
    }

    InspectorManager::reconcile_inspectors(other_conf, sc, true);
    InspectorManager::prepare_inspectors(sc);
    InspectorManager::prepare_controls(sc);

    other_conf->cloned = true;
    InspectorManager::update_policy(sc);
    reloading = false;
    return sc;
}

// -----------------------------------------------------------------------------
// unit tests
// -----------------------------------------------------------------------------

#ifdef UNIT_TEST

TEST_CASE("Check process ID handling", "[snort_process_id]")
{
    // Mock first process
    snort::SnortConfig* sc = const_cast<snort::SnortConfig*>(snort::SnortConfig::get_conf());
    snort::ThreadConfig::set_instance_max(4);
    sc->id_offset = 0;
    unsigned pid1 = Snort::get_process_id();
    CHECK(pid1 == 1);

    // Mock second process
    sc->id_offset = 5;
    unsigned pid2 = Snort::get_process_id();
    CHECK(pid2 == 2);

    // Mock third process
    sc->id_offset = 9;
    unsigned pid3 = Snort::get_process_id();
    CHECK(pid3 == 3);

    // Mock fourth process
    sc->id_offset = 13;
    unsigned pid4 = Snort::get_process_id();
    CHECK(pid4 == 4);

    // Restore prior configs
    snort::ThreadConfig::set_instance_max(1);
    sc->id_offset = 0;
}

#endif

<<<<<<< HEAD
=======
    pc.total_from_daq++;
    packet_time_update(&pkthdr->ts);

    if ( snort_conf->pkt_skip && pc.total_from_daq <= snort_conf->pkt_skip )
        return DAQ_VERDICT_PASS;

    s_switcher->start();
    s_packet = s_switcher->get_context()->packet;
    s_switcher->get_context()->pkt_count++;

    sfthreshold_reset();
    ActionManager::reset_queue();

    DAQ_Verdict verdict = process_packet(s_packet, pkthdr, pkt);
    ActionManager::execute(s_packet);

    int inject = 0;
    verdict = update_verdict(verdict, inject);

    // FIXIT-H move this to the appropriate struct
    //perfBase->UpdateWireStats(pkthdr->caplen, Active::packet_was_dropped(), inject);
    HighAvailabilityManager::process_update(s_packet->flow, pkthdr);

    Active::reset();
    Stream::timeout_flows(pkthdr->ts.tv_sec);
    HighAvailabilityManager::process_receive();

    s_packet->pkth = nullptr;  // no longer avail upon sig segv

    if ( snort_conf->pkt_cnt && pc.total_from_daq >= snort_conf->pkt_cnt )
        SFDAQ::break_loop(-1);

    else if ( break_time() )
        SFDAQ::break_loop(0);

    s_switcher->stop();

    return verdict;
}
>>>>>>> offload
