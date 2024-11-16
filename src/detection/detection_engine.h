//--------------------------------------------------------------------------
<<<<<<< HEAD
// Copyright (C) 2016-2024 Cisco and/or its affiliates. All rights reserved.
=======
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
>>>>>>> offload
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

// detection_engine_h author Russ Combs <rucombs@cisco.com>

#ifndef DETECTION_ENGINE_H
#define DETECTION_ENGINE_H

// DetectionEngine manages a detection context.  To detect a rebuilt
<<<<<<< HEAD
// packet (PDU), first call set_next_packet().  If rebuild is successful,
// then instantiate a new DetectionEngine to detect that packet.

#include "detection/detection_buf.h"
#include "detection/ips_context.h"
#include "main/snort_types.h"

struct OptTreeNode;
struct Replacement;

namespace snort
{
struct Packet;
class Flow;
class IpsContext;
class IpsContextChain;
=======
// packet (PDU), first call set_packet().  If rebuild is successful,
// then instantiate a new DetectionEngine to detect that packet.

#include "actions/actions.h"
#include "detection/detection_util.h"
#include "detection/ips_context.h"
#include "main/snort_types.h"

struct DataPointer;
struct Packet;

class Flow;
class IpsContext;
>>>>>>> offload
class IpsContextData;

class SO_PUBLIC DetectionEngine
{
public:
    DetectionEngine();
    ~DetectionEngine();

<<<<<<< HEAD
=======
    Packet* get_packet();

>>>>>>> offload
public:
    static void thread_init();
    static void thread_term();

<<<<<<< HEAD
    static void reset();

    static IpsContext* get_context();

    static Packet* get_current_packet();
    static Packet* get_current_wire_packet();
    static Packet* set_next_packet(const Packet* parent = nullptr, Flow* flow = nullptr);
    static uint8_t* get_next_buffer(unsigned& max);

    static void enable_offload();
    static bool offload(Packet*);

    static void onload(Flow*);
    static void onload();
=======
    static IpsContext* get_context();

    static Packet* get_current_packet();
    static Packet* set_packet();

    static bool offloaded(Packet*);
    static bool offload(Packet*);

    static void onload(Flow*);
>>>>>>> offload
    static void idle();

    static void set_encode_packet(Packet*);
    static Packet* get_encode_packet();

<<<<<<< HEAD
    static void set_file_data(const DataPointer& dp);
    static void set_file_data(const DataPointer& dp, uint64_t id, bool is_accum, bool no_flow);
    static const DataPointer& get_file_data(const IpsContext*);
    static const DataPointer& get_file_data(const IpsContext*, uint64_t& id, bool& drop_sse, bool& no_sse);

    static uint8_t* get_buffer(unsigned& max);
    static inline DataPointer get_alt_buffer(const Packet*);
    static inline DataBuffer& acquire_alt_buffer(const Packet*);
    static void inline reset_alt_buffer(Packet*);

    static void set_data(unsigned id, IpsContextData*);
    static IpsContextData* get_data(unsigned id);
    static IpsContextData* get_data(unsigned id, IpsContext*);

    static void add_replacement(const std::string&, unsigned);
    static bool get_replacement(std::string&, unsigned&);
    static void clear_replacement();

    static bool detect(Packet*, bool offload_ok = false);
    static bool inspect(Packet*);

    static int queue_event(const OptTreeNode*);
    static int queue_event(unsigned gid, unsigned sid);
=======
    static void set_next_file_data(const DataPointer&);
    static void get_next_file_data(DataPointer&);

    static void set_file_data(const DataPointer&);
    static void get_file_data(DataPointer&);

    static class MpseStash* get_stash();
    static uint8_t* get_buffer(unsigned& max);

    static void set_data(unsigned id, IpsContextData*);
    static IpsContextData* get_data(unsigned id);

    static bool detect(Packet*);
    static void inspect(Packet*);

    static int queue_event(const struct OptTreeNode*);
    static int queue_event(unsigned gid, unsigned sid, RuleType = RULE_TYPE__NONE);

    static int log_events(Packet*);
    static void reset(Packet*);
>>>>>>> offload

    static void disable_all(Packet*);
    static bool all_disabled(Packet*);

    static void disable_content(Packet*);
    static void enable_content(Packet*);
    static bool content_enabled(Packet*);

    static IpsContext::ActiveRules get_detects(Packet*);
    static void set_detects(Packet*, IpsContext::ActiveRules);

<<<<<<< HEAD
    static void set_check_tags(Packet*, bool enable = true);
    static bool get_check_tags(Packet*);

    static void wait_for_context();

private:
    static struct SF_EVENTQ* get_event_queue();
    static bool do_offload(snort::Packet*);
    static void offload_thread(IpsContext*);
    static void complete(snort::Packet*);
    static void resume(snort::Packet*);
    static void resume_ready_suspends(const IpsContextChain&);

    static int log_events(Packet*);
    static void clear_events(Packet*);
    static void finish_inspect_with_latency(Packet*);
    static void finish_inspect(Packet*, bool inspected);
    static void finish_packet(Packet*, bool flow_deletion = false);

private:
    static bool offload_enabled;
    IpsContext* context;
};

DataPointer DetectionEngine::get_alt_buffer(const Packet* p)
{
    assert(p);
    auto& alt_buf = p->context->alt_data;

    return { alt_buf.data, alt_buf.len };
}

DataBuffer& DetectionEngine::acquire_alt_buffer(const Packet* p)
{
    assert(p);

    auto& alt_buf = p->context->alt_data;

    if (!alt_buf.data)
        alt_buf.allocate_data();

    return alt_buf;
}

void snort::DetectionEngine::reset_alt_buffer(Packet *p)
{ p->context->alt_data.len = 0; }

=======
private:
    static struct SF_EVENTQ* get_event_queue();
    static void offload_thread(IpsContext*);
    static void onload();
    static void finish_packet(Packet*);

private:
    IpsContext* context;
};

static inline void set_next_file_data(const uint8_t* p, unsigned n)
{
    DataPointer dp { p, n };
    DetectionEngine::set_next_file_data(dp);
}

>>>>>>> offload
static inline void set_file_data(const uint8_t* p, unsigned n)
{
    DataPointer dp { p, n };
    DetectionEngine::set_file_data(dp);
}

<<<<<<< HEAD
static inline void set_file_data(const uint8_t* p, unsigned n, uint64_t id, bool is_accum = false, bool no_flow = false)
{
    DataPointer dp { p, n };
    DetectionEngine::set_file_data(dp, id, is_accum, no_flow);
}

static inline void clear_file_data()
{ set_file_data(nullptr, 0); }

} // namespace snort
=======
// FIXIT-H refactor detection resets
// this should only be called by framework
static inline void clear_file_data()
{ set_file_data(nullptr, 0); }
    
>>>>>>> offload
#endif

