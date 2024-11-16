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

// context_switcher.cc author Russ Combs <rucombs@cisco.com>

<<<<<<< HEAD
=======
#include "context_switcher.h"

>>>>>>> offload
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

<<<<<<< HEAD
#include "context_switcher.h"

#include <cassert>

#include "packet_io/active.h"
#include "trace/trace_api.h"
#include "utils/stats.h"

#include "detect_trace.h"
#include "ips_context.h"
#include "ips_context_data.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

static THREAD_LOCAL uint64_t global_context_num = 0;

=======
#include <assert.h>

#include "main/modules.h"
#include "main/snort_debug.h"
#include "utils/stats.h"

#include "ips_context.h"

#ifdef UNIT_TEST
#include "catch/catch.hpp"
#endif

>>>>>>> offload
//--------------------------------------------------------------------------
// context switcher methods
//--------------------------------------------------------------------------

<<<<<<< HEAD
=======
ContextSwitcher::ContextSwitcher(unsigned max) :
    hold(max+1, nullptr)  // use 1-based index / skip hold[0]
{
}

>>>>>>> offload
ContextSwitcher::~ContextSwitcher()
{
    abort();

<<<<<<< HEAD
    for ( const auto* p : contexts )
=======
    for ( auto* p : idle )
>>>>>>> offload
        delete p;
}

void ContextSwitcher::push(IpsContext* c)
{
<<<<<<< HEAD
    assert(c->state == IpsContext::IDLE);
    idle.emplace_back(c);
    contexts.emplace_back(c);
=======
    c->set_slot(idle.size() + 1);
    idle.push_back(c);
}

IpsContext* ContextSwitcher::pop()
{
    if ( idle.empty() )
        return nullptr;

    IpsContext* c = idle.back();
    idle.pop_back();
    return c;
>>>>>>> offload
}

void ContextSwitcher::start()
{
    assert(busy.empty());
<<<<<<< HEAD
    assert(!idle.empty());

    IpsContext* c = idle.back();
    assert(c->state == IpsContext::IDLE);
    assert(!c->has_callbacks());

    c->context_num = ++global_context_num;

    debug_logf(detection_trace, TRACE_DETECTION_ENGINE, nullptr,
        "(wire) %" PRIu64 " cs::start %" PRIu64 " (i=%zu, b=%zu)\n",
        pc.analyzed_pkts, c->context_num, idle.size(), busy.size());

    idle.pop_back();

    c->packet->active = c->packet->active_inst;
    c->packet->active->reset();
    c->packet->action = &c->packet->action_inst;
    c->state = IpsContext::BUSY;

    c->setup();

    busy.emplace_back(c);
=======
    assert(idle.size() > 0);
    trace_logf(detection, "%ld cs::start %u (i=%lu, b=%lu)\n",
        pc.total_from_daq, idle.back()->get_slot(), idle.size(), busy.size());
    busy.push_back(idle.back());
    idle.pop_back();
>>>>>>> offload
}

void ContextSwitcher::stop()
{
<<<<<<< HEAD
    IpsContext* c = busy.back();
    assert(c);
    assert(c->state == IpsContext::BUSY);
    assert(!c->has_callbacks());
    assert(!c->dependencies());

    debug_logf(detection_trace, TRACE_DETECTION_ENGINE, nullptr,
        "(wire) %" PRIu64 " cs::stop %" PRIu64 " (i=%zu, b=%zu)\n",
        pc.analyzed_pkts, c->context_num, idle.size(), busy.size());

    c->clear();

    c->packet->active = nullptr;
    c->packet->action = nullptr;
    c->state = IpsContext::IDLE;

    busy.pop_back();
    idle.emplace_back(c);
=======
    assert(busy.size() == 1);
    trace_logf(detection, "%ld cs::stop %u (i=%lu, b=%lu)\n",
        pc.total_from_daq, busy.back()->get_slot(), idle.size(), busy.size());
    idle.push_back(busy.back());
    busy.pop_back();
>>>>>>> offload
}

void ContextSwitcher::abort()
{
<<<<<<< HEAD
    debug_logf(detection_trace, TRACE_DETECTION_ENGINE, nullptr,
        "(wire) %" PRIu64 " cs::abort (i=%zu, b=%zu)\n",
        pc.analyzed_pkts, idle.size(), busy.size());

    busy.clear();

    for ( IpsContext* c : contexts )
    {
        switch ( c->state )
        {
            case IpsContext::IDLE:
                continue;
            case IpsContext::BUSY:
                debug_logf(detection_trace, TRACE_DETECTION_ENGINE, nullptr,
                    "%" PRIu64 " cs::abort busy", c->packet_number);
                break;
            case IpsContext::SUSPENDED:
                debug_logf(detection_trace, TRACE_DETECTION_ENGINE, nullptr,
                    "%" PRIu64 " cs::abort suspended", c->packet_number);
                break;
        }

        if ( c->packet->flow )
            c->packet->flow->context_chain.abort();

        c->abort();
        c->state = IpsContext::IDLE;
        c->clear_callbacks();
        c->clear();
        idle.emplace_back(c);
    }
    non_flow_chain.abort();
=======
    trace_logf(detection, "%ld cs::abort (i=%lu, b=%lu)\n",
        pc.total_from_daq, idle.size(), busy.size());
    for ( unsigned i = 0; i < hold.capacity(); ++i )
    {
        if ( hold[i] )
        {
            idle.push_back(hold[i]);
            hold[i] = nullptr;
        }
    }
    while ( !busy.empty() )
    {
        idle.push_back(busy.back());
        busy.pop_back();
    }
>>>>>>> offload
}

IpsContext* ContextSwitcher::interrupt()
{
    assert(!idle.empty());
<<<<<<< HEAD
    assert(!idle.back()->has_callbacks());

    IpsContext* c = idle.back();
    assert(c->state == IpsContext::IDLE);

    c->context_num = ++global_context_num;
    debug_logf(detection_trace, TRACE_DETECTION_ENGINE, nullptr,
        "%" PRIu64 " cs::interrupt %" PRIu64 " (i=%zu, b=%zu)\n",
        busy.empty() ? pc.analyzed_pkts : busy.back()->packet_number,
        busy.empty() ? 0 : busy.back()->context_num, idle.size(), busy.size());

    idle.pop_back();

    c->state = IpsContext::BUSY;
    c->setup();

    busy.emplace_back(c);
    return c;
=======
    trace_logf(detection, "%ld cs::interrupt %u (i=%lu, b=%lu)\n",
        pc.total_from_daq, idle.back()->get_slot(), idle.size(), busy.size());
    busy.push_back(idle.back());
    idle.pop_back();
    return busy.back();
>>>>>>> offload
}

IpsContext* ContextSwitcher::complete()
{
    assert(!busy.empty());
<<<<<<< HEAD

    IpsContext* c = busy.back();
    assert(c->state == IpsContext::BUSY);
    assert(!c->dependencies());
    assert(!c->has_callbacks());

    debug_logf(detection_trace, TRACE_DETECTION_ENGINE, nullptr,
        "%" PRIu64 " cs::complete %" PRIu64 " (i=%zu, b=%zu)\n",
        c->packet_number, c->context_num, idle.size(), busy.size());

    busy.pop_back();
    c->clear();
    c->state = IpsContext::IDLE;
    idle.emplace_back(c);

    if ( busy.empty() )
        return nullptr;

    return busy.back();
}

void ContextSwitcher::suspend()
{
    assert(!busy.empty());

    IpsContext* c = busy.back();
    assert(c->state == IpsContext::BUSY);

    debug_logf(detection_trace, TRACE_DETECTION_ENGINE, nullptr,
        "%" PRIu64 " cs::suspend %" PRIu64 " (i=%zu, b=%zu, wh=%zu)\n",
        c->packet_number, c->context_num, idle.size(), busy.size(),
        contexts.size() - idle.size() - busy.size());

    c->state = IpsContext::SUSPENDED;
    busy.pop_back();

    if ( c->packet->flow )
        c->packet->flow->context_chain.push_back(c);
    else
        non_flow_chain.push_back(c);
}

void ContextSwitcher::resume(IpsContext* c)
{
    assert(c->state == IpsContext::SUSPENDED);

    debug_logf(detection_trace, TRACE_DETECTION_ENGINE, nullptr,
        "%" PRIu64 " cs::resume %" PRIu64 " (i=%zu)\n",
        c->packet_number, c->context_num, idle.size());

    IpsContextChain& chain = c->packet->flow ? c->packet->flow->context_chain : non_flow_chain;
    assert(c == chain.front());
    assert(!c->dependencies());
    chain.pop();

    c->state = IpsContext::BUSY;
    busy.emplace_back(c);
=======
    trace_logf(detection, "%ld cs::complete %u (i=%lu, b=%lu)\n",
        pc.total_from_daq, busy.back()->get_slot(), idle.size(), busy.size());
    idle.push_back(busy.back());
    busy.pop_back();
    return busy.empty() ? nullptr : busy.back();
}

unsigned ContextSwitcher::suspend()
{
    assert(!busy.empty());
    trace_logf(detection, "%ld cs::suspend %u (i=%lu, b=%lu)\n",
        pc.total_from_daq, busy.back()->get_slot(), idle.size(), busy.size());
    IpsContext* c = busy.back();
    busy.pop_back();
    unsigned slot = c->get_slot();
    assert(!hold[slot]);
    hold[slot] = c;
    return slot;
}

void ContextSwitcher::resume(unsigned slot)
{
    assert(slot <= hold.capacity());
    trace_logf(detection, "%ld cs::resume %u (i=%lu, b=%lu)\n",
        pc.total_from_daq, slot, idle.size(), busy.size());
    busy.push_back(hold[slot]);
    hold[slot] = nullptr;
>>>>>>> offload
}

IpsContext* ContextSwitcher::get_context() const
{
<<<<<<< HEAD
    if ( busy.empty() )
        return nullptr;

    return busy.back();
}

=======
    assert(!busy.empty());
    return busy.back();
}

IpsContext* ContextSwitcher::get_context(unsigned slot) const
{
    assert(slot <= hold.capacity());
    IpsContext* c = hold[slot];
    assert(c);
    return c;
}

>>>>>>> offload
IpsContext* ContextSwitcher::get_next() const
{
    assert(!idle.empty());
    return idle.back();
}

IpsContextData* ContextSwitcher::get_context_data(unsigned id) const
<<<<<<< HEAD
{ return get_context()->get_context_data(id); }

void ContextSwitcher::set_context_data(unsigned id, IpsContextData* cd) const
{ get_context()->set_context_data(id, cd); }
=======
{
    return get_context()->get_context_data(id);
}

void ContextSwitcher::set_context_data(unsigned id, IpsContextData* cd) const
{
    get_context()->set_context_data(id, cd);
}
>>>>>>> offload

unsigned ContextSwitcher::idle_count() const
{ return idle.size(); }

unsigned ContextSwitcher::busy_count() const
{ return busy.size(); }

<<<<<<< HEAD
=======
unsigned ContextSwitcher::hold_count() const
{
    unsigned c = 0;

    for ( auto* p : hold )
        if ( p ) c++;

    return c;
}

bool ContextSwitcher::on_hold(Flow* f)
{
    for ( unsigned i = 0; i < hold.capacity(); ++i )
    {
        IpsContext* c = hold[i];
        if ( c and c->packet and c->packet->flow == f )
            return true;
    }
    return false;
}

>>>>>>> offload
//--------------------------------------------------------------------------
// unit tests
//--------------------------------------------------------------------------

#ifdef UNIT_TEST
class ContextData : public IpsContextData
{
public:
    ContextData(int) { }
};

<<<<<<< HEAD
TEST_CASE("ContextSwitcher single wire", "[ContextSwitcher]")
{
    const unsigned max = 10;
    ContextSwitcher mgr;

    for ( unsigned i = 0; i < max; ++i )
        mgr.push(new IpsContext);

    IpsContext *c1, *c2, *c3, *c4, *c5, *c6, *c7, *c8, *c9;

    /*
          __1__
         /     \
        _2_   _3_
       / | \ / | \
      *4*5 6 7 8 9

       6 2 7 8 9 3 1
    */

    mgr.start();

    c1 = mgr.get_context();
    CHECK(c1->state == IpsContext::BUSY);
    c2 = mgr.interrupt();
    CHECK(c2->state == IpsContext::BUSY);
    c4 = mgr.interrupt();
    CHECK(c4->state == IpsContext::BUSY);

    mgr.complete();
    CHECK(c4->state == IpsContext::IDLE);

    c5 = mgr.interrupt();
    CHECK(c5->state == IpsContext::BUSY);
    mgr.complete();
    CHECK(c5->state == IpsContext::IDLE);

    c6 = mgr.interrupt();
    CHECK(c6->state == IpsContext::BUSY);
    c6->packet->set_offloaded();
    mgr.suspend();
    CHECK(c6->state == IpsContext::SUSPENDED);
    CHECK(mgr.non_flow_chain.front() == c6);

    mgr.suspend();
    CHECK(c6->next() == c2);
    CHECK(c2->state == IpsContext::SUSPENDED);
    CHECK(mgr.non_flow_chain.front() == c6);

    c3 = mgr.interrupt();
    CHECK(c3->state == IpsContext::BUSY);
    c7 = mgr.interrupt();
    CHECK(c7->state == IpsContext::BUSY);
    mgr.suspend();
    CHECK(c2->next() == c7);
    CHECK(c7->state == IpsContext::SUSPENDED);

    c8 = mgr.interrupt();
    CHECK(c8->state == IpsContext::BUSY);
    mgr.suspend();
    CHECK(c7->next() == c8);
    CHECK(c8->state == IpsContext::SUSPENDED);

    c9 = mgr.interrupt();
    CHECK(c9->state == IpsContext::BUSY);
    mgr.suspend();
    CHECK(c8->next() == c9);
    CHECK(c9->state == IpsContext::SUSPENDED);

    mgr.suspend();
    CHECK(c9->next() == c3);
    CHECK(c3->state == IpsContext::SUSPENDED);

    mgr.suspend();
    CHECK(c3->next() == c1);
    CHECK(c1->state == IpsContext::SUSPENDED);

    std::vector<IpsContext*> expected = { c6, c2, c7, c8, c9, c3, c1 };

    for ( auto& e : expected )
    {
        mgr.resume(e);
        CHECK(mgr.get_context() == e);
        CHECK(e->state == IpsContext::BUSY);

        if ( e == c1 )
            mgr.stop();
        else
            mgr.complete();

        CHECK(e->state == IpsContext::IDLE);
    }
}

TEST_CASE("ContextSwitcher multi wire", "[ContextSwitcher]")
{
    const unsigned max = 3;
    ContextSwitcher mgr;

    IpsContext *c1, *c2, *c3;
    for ( unsigned i = 0; i < max; ++i )
    {
        IpsContext* c = new IpsContext;
        c->packet->flow = new Flow;
        mgr.push(c);
    }

    mgr.start();
    c1 = mgr.get_context();
    mgr.suspend();
    CHECK(mgr.busy_count() == 0);

    mgr.start();
    c2 = mgr.get_context();
    mgr.suspend();
    CHECK(mgr.busy_count() == 0);

    mgr.start();
    c3 = mgr.get_context();
    mgr.suspend();
    CHECK(mgr.busy_count() == 0);

    // middle
    CHECK(c2->state == IpsContext::SUSPENDED);
    mgr.resume(c2);
    CHECK(c2->state == IpsContext::BUSY);
    CHECK(mgr.get_context() == c2);
    CHECK(mgr.busy_count() == 1);

    mgr.stop();
    CHECK(c2->state == IpsContext::IDLE);
    CHECK(mgr.busy_count() == 0);

    // end
    CHECK(c3->state == IpsContext::SUSPENDED);
    mgr.resume(c3);
    CHECK(c3->state == IpsContext::BUSY);
    CHECK(mgr.get_context() == c3);
    CHECK(mgr.busy_count() == 1);

    mgr.stop();
    CHECK(c3->state == IpsContext::IDLE);
    CHECK(mgr.busy_count() == 0);

    // only
    CHECK(c1->state == IpsContext::SUSPENDED);
    mgr.resume(c1);
    CHECK(c1->state == IpsContext::BUSY);
    CHECK(mgr.busy_count() == 1);

    mgr.stop();
    CHECK(c1->state == IpsContext::IDLE);
    CHECK(mgr.busy_count() == 0);

    delete c1->packet->flow;
    delete c2->packet->flow;
    delete c3->packet->flow;
=======
TEST_CASE("ContextSwitcher normal", "[ContextSwitcher]")
{
    const unsigned max = 3;
    auto mgr = ContextSwitcher(max);
    auto id = IpsContextData::get_ips_id();
    CHECK(!mgr.pop());

    for ( unsigned i = 0; i < max; ++i )
        mgr.push(new IpsContext(id+1));

    SECTION("workflow")
    {
        CHECK(mgr.idle_count() == max);

        mgr.start();
        CHECK(mgr.idle_count() == max-1);
        CHECK(mgr.busy_count() == 1);

        IpsContextData* a = new ContextData(id);
        mgr.set_context_data(1, a);
        mgr.interrupt();
        CHECK(mgr.idle_count() == max-2);
        CHECK(mgr.busy_count() == 2);

        unsigned u = mgr.suspend();
        CHECK(mgr.idle_count() == max-2);
        CHECK(mgr.busy_count() == 1);
        CHECK(mgr.hold_count() == 1);

        mgr.resume(u);
        CHECK(mgr.idle_count() == max-2);
        CHECK(mgr.busy_count() == 2);
        CHECK(mgr.hold_count() == 0);

        mgr.complete();
        CHECK(mgr.idle_count() == max-1);
        CHECK(mgr.busy_count() == 1);

        IpsContextData* b = mgr.get_context_data(1);
        CHECK(a == b);

        mgr.stop();
        CHECK(mgr.idle_count() == max);
    }
    for ( unsigned i = 0; i < max; ++i )
    {
        IpsContext* p = mgr.pop();
        CHECK(p);
        delete p;
    }
    CHECK(!mgr.pop());
>>>>>>> offload
}

TEST_CASE("ContextSwitcher abort", "[ContextSwitcher]")
{
    const unsigned max = 3;
<<<<<<< HEAD
    ContextSwitcher mgr;
    auto id = IpsContextData::get_ips_id();
=======
    auto mgr = ContextSwitcher(max);
    auto id = IpsContextData::get_ips_id();
    CHECK(!mgr.pop());
>>>>>>> offload

    for ( unsigned i = 0; i < max; ++i )
        mgr.push(new IpsContext(id+1));

<<<<<<< HEAD
    mgr.start();
    IpsContextData* a = new ContextData(id);
    mgr.set_context_data(1, a);
    mgr.interrupt();
    mgr.interrupt();
    CHECK(mgr.idle_count() == max-3);

    mgr.suspend();
    CHECK((mgr.busy_count() == 2));

    mgr.abort();
    CHECK(mgr.idle_count() == max);
    CHECK(!mgr.busy_count());
=======
    SECTION("cleanup")
    {
        mgr.start();
        IpsContextData* a = new ContextData(id);
        mgr.set_context_data(1, a);
        mgr.interrupt();
        mgr.interrupt();
        CHECK(mgr.idle_count() == max-3);

        mgr.suspend();
        CHECK(mgr.busy_count() == 2);
        CHECK(mgr.hold_count() == 1);

        mgr.abort();
        CHECK(mgr.idle_count() == max);
    }
>>>>>>> offload
}
#endif

