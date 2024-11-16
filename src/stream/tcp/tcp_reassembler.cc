//--------------------------------------------------------------------------
// Copyright (C) 2015-2024 Cisco and/or its affiliates. All rights reserved.
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

// tcp_reassembler.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: Jul 31, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_reassembler.h"

<<<<<<< HEAD
#include <cassert>

=======
>>>>>>> offload
#include "detection/detection_engine.h"
#include "log/log.h"
#include "packet_io/active.h"
#include "packet_io/packet_tracer.h"
#include "profiler/profiler.h"
#include "detection/detection_engine.h"
#include "protocols/packet_manager.h"
<<<<<<< HEAD
#include "stream/stream_splitter.h"
=======
>>>>>>> offload
#include "time/packet_time.h"

#include "tcp_module.h"
#include "tcp_normalizers.h"
#include "tcp_segment_node.h"
#include "tcp_session.h"

<<<<<<< HEAD
using namespace snort;
=======
static THREAD_LOCAL Packet* s5_pkt = nullptr;
>>>>>>> offload

void TcpReassembler::init(bool server, StreamSplitter* ss)
{
    splitter = ss;
    paf.paf_setup(ss);
    if ( seglist.cur_rseg )
        seglist.cur_sseg = seglist.cur_rseg;
    else
        seglist.cur_sseg = seglist.head;

    server_side = server;

    if ( server_side )
    {
        ignore_dir = SSN_DIR_FROM_CLIENT;
        packet_dir = PKT_FROM_CLIENT;
    }
    else
    {
        ignore_dir = SSN_DIR_FROM_SERVER;
        packet_dir = PKT_FROM_SERVER;
    }
}

bool TcpReassembler::fin_no_gap(const TcpSegmentNode& tsn)
{
    return tracker.fin_seq_status >= FIN_WITH_SEQ_SEEN
        and SEQ_GEQ(tsn.next_seq(), tracker.get_fin_i_seq());
}

bool TcpReassembler::fin_acked_no_gap(const TcpSegmentNode& tsn)
{
    return tracker.fin_seq_status >= FIN_WITH_SEQ_ACKED
        and SEQ_GEQ(tsn.next_seq(), tracker.get_fin_i_seq());
}

// If we are skipping seglist hole, update tsn so that we can purge
void TcpReassembler::update_skipped_bytes(uint32_t remaining_bytes)
{
    TcpSegmentNode* tsn;

    while ( remaining_bytes and (tsn = seglist.cur_rseg) )
    {
        auto bytes_skipped = ( tsn->unscanned() <= remaining_bytes ) ? tsn->unscanned() : remaining_bytes;

        remaining_bytes -= bytes_skipped;
        tsn->advance_cursor(bytes_skipped);

        if ( !tsn->unscanned() )
        {
            seglist.flush_count++;
            seglist.update_next(tsn);
        }
    }
}

void TcpReassembler::purge_to_seq(uint32_t flush_seq)
{
    seglist.purge_flushed_segments(flush_seq);

    if ( last_pdu )
    {
        tracker.tcp_alerts.purge_alerts(*last_pdu, tracker.normalizer.is_tcp_ips_enabled());
        last_pdu = nullptr;
    }
    else
        tracker.tcp_alerts.purge_alerts(seglist.session->flow);
}

// must only purge flushed and acked bytes we may flush partial segments
// must adjust seq->seq and tsn->size when a flush gets only the initial
// part of a segment
// * FIXIT-L need flag to mark any reassembled packets that have a gap
//   (if we reassemble such)
void TcpReassembler::purge_flushed_ackd()
{
    if ( !seglist.head )
        return;

    uint32_t seq = seglist.head->start_seq();
    TcpSegmentNode* tsn = seglist.head;
    while ( tsn && !tsn->unscanned() )
    {
        uint32_t end = tsn->next_seq();

        if ( SEQ_GT(end, tracker.r_win_base) )
            break;

        seq = end;
        tsn = tsn->next;
    }

    if ( !SEQ_EQ(seq, seglist.head->start_seq()) )
        purge_to_seq(seq);
}

void TcpReassembler::show_rebuilt_packet(Packet* pkt)
{
    if ( seglist.session->tcp_config->flags & STREAM_CONFIG_SHOW_PACKETS )
    {
        // FIXIT-L setting conf here is required because this is called before context start
        pkt->context->conf = SnortConfig::get_conf();
        LogFlow(pkt);
        LogNetData(pkt->data, pkt->dsize, pkt);
    }
}

int TcpReassembler::flush_data_segments(uint32_t flush_len, Packet* pdu)
{
    uint32_t flags = PKT_PDU_HEAD;

    uint32_t to_seq = seglist.cur_rseg->scan_seq() + flush_len;
    uint32_t remaining_bytes = flush_len;
    uint32_t total_flushed = 0;

    while ( remaining_bytes )
    {
        TcpSegmentNode* tsn = seglist.cur_rseg;
        unsigned bytes_to_copy = ( tsn->unscanned() <= remaining_bytes ) ? tsn->unscanned() : remaining_bytes;

        remaining_bytes -= bytes_to_copy;
        if ( !remaining_bytes )
            flags |= PKT_PDU_TAIL;
        else
            assert( bytes_to_copy >= tsn->unscanned() );

<<<<<<< HEAD
        unsigned bytes_copied = 0;
        const StreamBuffer sb = splitter->reassemble(seglist.session->flow, flush_len, total_flushed,
            tsn->paf_data(), bytes_to_copy, flags, bytes_copied);
=======
        const StreamBuffer sb = tracker->splitter->reassemble(
            session->flow, total, bytes_flushed, tsn->payload(),
            bytes_to_copy, flags, bytes_copied);
>>>>>>> offload

        if ( sb.data )
        {
            pdu->data = sb.data;
            pdu->dsize = sb.length;
        }

        total_flushed += bytes_copied;
        tsn->advance_cursor(bytes_copied);
        flags = 0;

<<<<<<< HEAD
        if ( !tsn->unscanned() )
        {
            seglist.flush_count++;
            seglist.update_next(tsn);
=======
        if ( sb.data )
        {
            s5_pkt->data = sb.data;
            s5_pkt->dsize = sb.length;
            assert(sb.length <= s5_pkt->max_dsize);

            bytes_to_copy = bytes_copied;
>>>>>>> offload
        }

        /* Check for a gap/missing packet */
        // FIXIT-L FIN may be in to_seq causing bogus gap counts.
        if ( tsn->is_packet_missing(to_seq) or paf.state == StreamSplitter::SKIP )
        {
            // FIXIT-H // assert(false); find when this scenario happens
            // FIXIT-L this is suboptimal - better to exclude fin from to_seq
            if ( !tracker.is_fin_seq_set() or
                SEQ_LEQ(to_seq, tracker.get_fin_final_seq()) )
            {
                tracker.set_tf_flags(TF_MISSING_PKT);
            }
            break;
        }

<<<<<<< HEAD
        if ( sb.data || !seglist.cur_rseg )
=======
        if ( sb.data || !seglist.next )
            break;

        if ( bytes_flushed + seglist.next->payload_size >= StreamSplitter::max_buf )
>>>>>>> offload
            break;
    }

    if ( paf.state == StreamSplitter::SKIP )
        update_skipped_bytes(remaining_bytes);

    return total_flushed;
}

// FIXIT-L consolidate encode format, update, and this into new function?
void TcpReassembler::prep_pdu(Flow* flow, Packet* p, uint32_t pkt_flags, Packet* pdu)
{
    pdu->ptrs.set_pkt_type(PktType::PDU);
    pdu->proto_bits |= PROTO_BIT__TCP;
    pdu->packet_flags |= (pkt_flags & PKT_PDU_FULL);
    pdu->flow = flow;

    if (p == pdu)
    {
        // final
        if (pkt_flags & PKT_FROM_SERVER)
        {
            pdu->packet_flags |= PKT_FROM_SERVER;
            pdu->ptrs.ip_api.set(flow->server_ip, flow->client_ip);
            pdu->ptrs.sp = flow->server_port;
            pdu->ptrs.dp = flow->client_port;
        }
        else
        {
            pdu->packet_flags |= PKT_FROM_CLIENT;
            pdu->ptrs.ip_api.set(flow->client_ip, flow->server_ip);
            pdu->ptrs.sp = flow->client_port;
            pdu->ptrs.dp = flow->server_port;
        }
    }
    else if (!p->packet_flags || (pkt_flags & p->packet_flags))
    {
        // forward
        pdu->packet_flags |= (p->packet_flags & (PKT_FROM_CLIENT | PKT_FROM_SERVER));
        pdu->ptrs.ip_api.set(*p->ptrs.ip_api.get_src(), *p->ptrs.ip_api.get_dst());
        pdu->ptrs.sp = p->ptrs.sp;
        pdu->ptrs.dp = p->ptrs.dp;
    }
    else
    {
        // reverse
        if (p->is_from_client())
            pdu->packet_flags |= PKT_FROM_SERVER;
        else
            pdu->packet_flags |= PKT_FROM_CLIENT;

        pdu->ptrs.ip_api.set(*p->ptrs.ip_api.get_dst(), *p->ptrs.ip_api.get_src());
        pdu->ptrs.dp = p->ptrs.sp;
        pdu->ptrs.sp = p->ptrs.dp;
    }
}

Packet* TcpReassembler::initialize_pdu(Packet* p, uint32_t pkt_flags, struct timeval tv)
{
    // partial flushes already set the pdu for http_inspect splitter processing
    Packet* pdu = p->was_set() ? p : DetectionEngine::set_next_packet(p);

<<<<<<< HEAD
    EncodeFlags enc_flags = 0;
    DAQ_PktHdr_t pkth;
    seglist.session->get_packet_header_foo(&pkth, p->pkth, pkt_flags);
    PacketManager::format_tcp(enc_flags, p, pdu, PSEUDO_PKT_TCP, &pkth, pkth.opaque);
    prep_pdu(seglist.session->flow, p, pkt_flags, pdu);
    assert(pdu->pkth == pdu->context->pkth);
    pdu->context->pkth->ts = tv;
    pdu->dsize = 0;
    pdu->data = nullptr;
    pdu->ip_proto_next = (IpProtocol)p->flow->ip_proto;

=======
    DetectionEngine::onload(session->flow);
    s5_pkt = DetectionEngine::set_packet();

    DAQ_PktHdr_t pkth;
    session->GetPacketHeaderFoo(&pkth, pkt_flags);

    if ( !p )
    {
        // FIXIT-H we need to have user_policy_id in this case
        // FIXIT-H this leads to format_tcp() copying from s5_pkt to s5_pkt
        // (neither of these issues is created by passing null through to here)
        p = s5_pkt;
    }

    EncodeFlags enc_flags = 0;
    PacketManager::format_tcp(enc_flags, p, s5_pkt, PSEUDO_PKT_TCP, &pkth, pkth.opaque);
    prep_s5_pkt(session->flow, p, pkt_flags);
>>>>>>> offload

    if ( p->proto_bits & PROTO_BIT__VLAN )
    {
<<<<<<< HEAD
        memcpy( pdu->layers, p->layers, p->num_layers * sizeof(Layer));
        pdu->num_layers = p->num_layers;
        pdu->proto_bits |= PROTO_BIT__VLAN;
        pdu->vlan_idx = p->vlan_idx;
=======
        seglist_base_seq = seglist.next->seq;
        uint32_t footprint = stop_seq - seglist_base_seq;

        if ( footprint == 0 )
            return bytes_processed;

        if ( footprint > s5_pkt->max_dsize )
            /* this is as much as we can pack into a stream buffer */
            footprint = s5_pkt->max_dsize;

        DetectionEngine::onload(session->flow);
        s5_pkt = DetectionEngine::set_packet();

        DAQ_PktHdr_t pkth;
        session->GetPacketHeaderFoo(&pkth, pkt_flags);

        PacketManager::format_tcp(enc_flags, p, s5_pkt, PSEUDO_PKT_TCP, &pkth, pkth.opaque);
        prep_s5_pkt(session->flow, p, pkt_flags);

        ((DAQ_PktHdr_t*)s5_pkt->pkth)->ts = seglist.next->tv;

        /* setup the pseudopacket payload */
        s5_pkt->dsize = 0;
        s5_pkt->data = nullptr;

        if ( tracker->splitter->is_paf() and tracker->get_tf_flags() & TF_MISSING_PREV_PKT )
            fallback();

        int32_t flushed_bytes = flush_data_segments(p, footprint);

        if ( flushed_bytes == 0 )
            break; /* No more data... bail */

        bytes_processed += flushed_bytes;
        seglist_base_seq += flushed_bytes;

        if ( s5_pkt->dsize )
        {
            if ( p->packet_flags & PKT_PDU_TAIL )
                s5_pkt->packet_flags |= ( PKT_REBUILT_STREAM | PKT_STREAM_EST | PKT_PDU_TAIL );
            else
                s5_pkt->packet_flags |= ( PKT_REBUILT_STREAM | PKT_STREAM_EST );

            // FIXIT-H this came with merge should it be here? YES
            //s5_pkt->application_protocol_ordinal =
            //    p->application_protocol_ordinal;

            show_rebuilt_packet(s5_pkt);
            tcpStats.rebuilt_packets++;
            tcpStats.rebuilt_bytes += flushed_bytes;

            ProfileExclude profile_exclude(s5TcpFlushPerfStats);
            Snort::inspect(s5_pkt);
        }
        else
        {
            tcpStats.rebuilt_buffers++; // FIXIT-L this is not accurate
        }

        DebugFormat(DEBUG_STREAM_STATE, "setting seglist_base_seq to 0x%X\n", seglist_base_seq);

        if ( tracker->splitter )
            // FIXIT-L must check because above may clear session
            tracker->splitter->update();

        // FIXIT-L abort should be by PAF callback only since recovery may be
        // possible in some cases
        if ( tracker->get_tf_flags() & TF_MISSING_PKT )
        {
            tracker->set_tf_flags(TF_MISSING_PREV_PKT | TF_PKT_MISSED);
            tracker->clear_tf_flags(TF_MISSING_PKT);
            tcpStats.gaps++;
        }
        else
            tracker->clear_tf_flags(TF_MISSING_PREV_PKT);

        // check here instead of in while to allow single segment flushes
        if ( !flush_data_ready() )
            break;
>>>>>>> offload
    }

    return pdu;
}

// flush a seglist up to the given point, generate a pseudopacket, and fire it thru the system.
int TcpReassembler::flush_to_seq(uint32_t bytes, Packet* p, uint32_t pkt_flags)
{
    assert( p && seglist.cur_rseg);

    tracker.clear_tf_flags(TF_MISSING_PKT | TF_MISSING_PREV_PKT);

    TcpSegmentNode* tsn = seglist.cur_rseg;
    assert( seglist.seglist_base_seq == tsn->scan_seq());

    Packet* pdu = initialize_pdu(p, pkt_flags, tsn->tv);
    int32_t flushed_bytes = flush_data_segments(bytes, pdu);
    assert( flushed_bytes );

    seglist.seglist_base_seq += flushed_bytes;

    if ( pdu->data )
    {
        if ( p->packet_flags & PKT_PDU_TAIL )
            pdu->packet_flags |= ( PKT_REBUILT_STREAM | PKT_STREAM_EST | PKT_PDU_TAIL );
        else
            pdu->packet_flags |= ( PKT_REBUILT_STREAM | PKT_STREAM_EST );

        show_rebuilt_packet(pdu);
        tcpStats.rebuilt_packets++;
        tcpStats.rebuilt_bytes += flushed_bytes;

        DetectionEngine de;

        if ( !de.inspect(pdu) )
            last_pdu = pdu;
        else
            last_pdu = nullptr;

        tracker.finalize_held_packet(p);
    }
    else
    {
        tcpStats.rebuilt_buffers++; // FIXIT-L this is not accurate
        last_pdu = nullptr;
    }

    // FIXIT-L abort should be by PAF callback only since recovery may be possible
    if ( tracker.get_tf_flags() & TF_MISSING_PKT )
    {
        tracker.set_tf_flags(TF_MISSING_PREV_PKT | TF_PKT_MISSED);
        tracker.clear_tf_flags(TF_MISSING_PKT);
        tcpStats.gaps++;
    }
    else
        tracker.clear_tf_flags(TF_MISSING_PREV_PKT);

    return flushed_bytes;
}

int TcpReassembler::do_zero_byte_flush(Packet* p, uint32_t pkt_flags)
{
    unsigned bytes_copied = 0;

    const StreamBuffer sb = splitter->reassemble(seglist.session->flow, 0, 0,
        nullptr, 0, (PKT_PDU_HEAD | PKT_PDU_TAIL), bytes_copied);

     if ( sb.data )
     {
        Packet* pdu = initialize_pdu(p, pkt_flags, p->pkth->ts);
        /* setup the pseudopacket payload */
        pdu->data = sb.data;
        pdu->dsize = sb.length;
        pdu->packet_flags |= (PKT_REBUILT_STREAM | PKT_STREAM_EST | PKT_PDU_HEAD | PKT_PDU_TAIL);

        show_rebuilt_packet(pdu);

        DetectionEngine de;
        de.inspect(pdu);
     }

     return bytes_copied;
}

// get the footprint for the current seglist, the difference
// between our base sequence and the last ack'd sequence we received

uint32_t TcpReassembler::get_q_footprint()
{
    int32_t footprint = 0;
    int32_t sequenced = 0;

    if ( SEQ_GT(tracker.r_win_base, seglist.seglist_base_seq) )
        footprint = tracker.r_win_base - seglist.seglist_base_seq;

    if ( footprint )
        sequenced = get_q_sequenced();

    return ( footprint > sequenced ) ? sequenced : footprint;
}

// FIXIT-P get_q_sequenced() performance could possibly be
// boosted by tracking sequenced bytes as seglist is updated
// to avoid the while loop, etc. below.

uint32_t TcpReassembler::get_q_sequenced()
{
    TcpSegmentNode* tsn = seglist.cur_rseg;

    if ( !tsn )
    {
        tsn = seglist.head;

        if ( !tsn || SEQ_LT(tracker.r_win_base, tsn->scan_seq()) )
            return 0;

        seglist.cur_rseg = tsn;
    }

    uint32_t len = 0;
    const uint32_t limit = splitter->max();
    while ( len < limit and tsn->next_no_gap() )
    {

        if ( !tsn->unscanned() )
            seglist.cur_rseg = tsn->next;
        else
            len += tsn->unscanned();

        tsn = tsn->next;
    }
    if ( tsn->unscanned() )
        len += tsn->unscanned();

    seglist.seglist_base_seq = seglist.cur_rseg->scan_seq();

    return len;
}

bool TcpReassembler::is_q_sequenced()
{
    TcpSegmentNode* tsn = seglist.cur_rseg;

<<<<<<< HEAD
    if ( !tsn )
    {
        tsn = seglist.head;
        if ( !tsn || SEQ_LT(tracker.r_win_base, tsn->scan_seq()) )
            return false;

        seglist.cur_rseg = tsn;
    }

    while ( tsn->next_no_gap() )
    {
        if ( tsn->unscanned() )
            break;
=======
    uint32_t bytes;

    if ( tracker->normalizer->is_tcp_ips_enabled() )
        bytes = get_q_sequenced( );
    else
        bytes = get_q_footprint( );

    return flush_to_seq(bytes, p, dir);
}

void TcpReassembler::final_flush(Packet* p, uint32_t dir)
{
    tracker->set_tf_flags(TF_FORCE_FLUSH);
>>>>>>> offload

        tsn = seglist.cur_rseg = tsn->next;
    }

    seglist.seglist_base_seq = tsn->scan_seq();

    return (tsn->unscanned() != 0);
}

<<<<<<< HEAD
void TcpReassembler::final_flush(Packet* p, uint32_t dir)
{
    tracker.set_tf_flags(TF_FORCE_FLUSH);

    if ( flush_stream(p, dir, true) )
    {
        if ( server_side )
            tcpStats.server_cleanups++;
        else
            tcpStats.client_cleanups++;

        purge_flushed_ackd();
    }
    tracker.clear_tf_flags(TF_FORCE_FLUSH);
}

static Packet* get_packet(Flow* flow, uint32_t flags, bool c2s)
{
    Packet* p = DetectionEngine::set_next_packet(nullptr, flow);

    DAQ_PktHdr_t* ph = p->context->pkth;
    memset(ph, 0, sizeof(*ph));
    packet_gettimeofday(&ph->ts);

    p->pktlen = 0;
    p->data = nullptr;
    p->dsize = 0;

    p->ptrs.set_pkt_type(PktType::PDU);
    p->proto_bits |= PROTO_BIT__TCP;
    p->flow = flow;
    p->packet_flags |= flags;
=======
static Packet* set_packet(Flow* flow, uint32_t flags, bool c2s)
{
    Packet* p = DetectionEngine::get_current_packet();
    p->reset();

    DAQ_PktHdr_t* ph = (DAQ_PktHdr_t*)p->pkth;
    memset(ph, 0, sizeof(*ph));
    packet_gettimeofday(&ph->ts);

    p->ptrs.set_pkt_type(PktType::PDU);
    p->proto_bits |= PROTO_BIT__TCP;
    p->flow = flow;
    p->packet_flags = flags;
>>>>>>> offload

    if ( c2s )
    {
        p->ptrs.ip_api.set(flow->client_ip, flow->server_ip);
        p->ptrs.sp = flow->client_port;
        p->ptrs.dp = flow->server_port;
    }
    else
    {
        p->ptrs.ip_api.set(flow->server_ip, flow->client_ip);
        p->ptrs.sp = flow->server_port;
        p->ptrs.dp = flow->client_port;
    }
<<<<<<< HEAD

    p->ip_proto_next = (IpProtocol)flow->ip_proto;

    set_inspection_policy(flow->inspection_policy_id);
    const SnortConfig* sc = SnortConfig::get_conf();
    set_ips_policy(sc, flow->ips_policy_id);

    return p;
}

bool TcpReassembler::splitter_finish(snort::Flow* flow)
{
    if (!splitter)
        return true;

    if (!splitter_finish_flag)
    {
        splitter_finish_flag = true;
        return splitter->finish(flow);
    }
    // there shouldn't be any un-flushed data beyond this point,
    // returning false here, discards it
    return false;
}

void TcpReassembler::finish_and_final_flush(Flow* flow, bool clear, Packet* p)
{
    bool pending = clear and paf.paf_initialized() and splitter_finish(flow);

    if ( pending and !(flow->ssn_state.ignore_direction & ignore_dir) )
        final_flush(p, packet_dir);
}

// Call this only from outside reassembly.
void TcpReassembler::flush_queued_segments(Flow* flow, bool clear, Packet* p)
{
    if ( p )
    {
        finish_and_final_flush(flow, clear, p);
    }
    else
    {
        Packet* pdu = get_packet(flow, packet_dir, server_side);

        bool pending = clear and paf.paf_initialized();
        if ( pending )
        {
            DetectionEngine de;
            pending = splitter_finish(flow);
        }

        if ( pending and !(flow->ssn_state.ignore_direction & ignore_dir) )
            final_flush(pdu, packet_dir);
=======
    return p;
}

void TcpReassembler::flush_queued_segments(Flow* flow, bool clear, Packet* p)
{
    bool data = p or seglist.head;

    if ( !p )
    {
        // this packet is required if we call finish and/or final_flush
        p = set_packet(flow, packet_dir, server_side);

        if ( server_side )
            tcpStats.s5tcp2++;
        else
            tcpStats.s5tcp1++;
    }

    bool pending = clear and paf_initialized(&tracker->paf_state)
        and (!tracker->splitter or tracker->splitter->finish(flow) );

    if ( pending and data and !(flow->ssn_state.ignore_direction & ignore_dir) )
    {
        final_flush(p, packet_dir);
>>>>>>> offload
    }
}


void TcpReassembler::check_first_segment_hole()
{
    if ( SEQ_LT(seglist.seglist_base_seq, seglist.head->start_seq()) )
    {
        seglist.seglist_base_seq = seglist.head->start_seq();
        seglist.advance_rcv_nxt();
        paf.state = StreamSplitter::START;
    }
}

uint32_t TcpReassembler::perform_partial_flush(Flow* flow, Packet*& p)
{
    p = get_packet(flow, packet_dir, server_side);
    return perform_partial_flush(p);
}

<<<<<<< HEAD
// No error checking here, so the caller must ensure that p, p->flow are not null.
uint32_t TcpReassembler::perform_partial_flush(Packet* p)
=======
// iterate over seglist and scan all new acked bytes
// - new means not yet scanned
// - must use seglist data (not packet) since this packet may plug a
//   hole and enable paf scanning of following segments
// - if we reach a flush point
//   - return bytes to flush if data available (must be acked)
//   - return zero if not yet received or received but not acked
// - if we reach a skip point
//   - jump ahead and resume scanning any available data
// - must stop if we reach a gap
// - one segment may lead to multiple checks since
//   it may contain multiple encapsulated PDUs
// - if we partially scan a segment we must save state so we
//   know where we left off and can resume scanning the remainder

int32_t TcpReassembler::flush_pdu_ackd(uint32_t* flags)
{
    Profile profile(s5TcpPAFPerfStats);
    DetectionEngine::onload(session->flow);

    uint32_t total = 0;
    TcpSegmentNode* tsn = SEQ_LT(seglist_base_seq, tracker->r_win_base) ? seglist.head : nullptr;

    // must stop if not acked
    // must use adjusted size of tsn if not fully acked
    // must stop if gap (checked in paf_check)
    while (tsn && *flags && SEQ_LT(tsn->seq, tracker->r_win_base))
    {
        int32_t flush_pt;
        uint32_t size = tsn->payload_size;
        uint32_t end = tsn->seq + tsn->payload_size;
        uint32_t pos = paf_position(&tracker->paf_state);

        if ( paf_initialized(&tracker->paf_state) && SEQ_LEQ(end, pos) )
        {
            total += size;
            tsn = tsn->next;
            continue;
        }
        if ( SEQ_GT(end, tracker->r_win_base))
            size = tracker->r_win_base - tsn->seq;

        total += size;

        flush_pt = paf_check(tracker->splitter, &tracker->paf_state, session->flow,
            tsn->payload(), size, total, tsn->seq, flags);

        if ( flush_pt >= 0 )
        {
            // for non-paf splitters, flush_pt > 0 means we reached
            // the minimum required, but we flush what is available
            // instead of creating more, but smaller, packets
            // FIXIT-L just flush to end of segment to avoid splitting
            // instead of all avail?
            if ( !tracker->splitter->is_paf() )
            {
                // get_q_footprint() w/o side effects
                int32_t avail = tracker->r_win_base - seglist_base_seq;
                if ( avail > flush_pt )
                {
                    paf_jump(&tracker->paf_state, avail - flush_pt);
                    return avail;
                }
            }
            return flush_pt;
        }
        tsn = tsn->next;
    }

    return -1;
}

int TcpReassembler::flush_on_data_policy(Packet* p)
>>>>>>> offload
{
    uint32_t flushed = 0;
    if ( splitter->init_partial_flush(p->flow) )
    {
        flushed = flush_stream(p, packet_dir, false);
        paf.paf_jump(flushed);
        tcpStats.partial_flushes++;
        tcpStats.partial_flush_bytes += flushed;
        if ( seglist.seg_count )
        {
            purge_to_seq(seglist.head->start_seq() + flushed);
            tracker.r_win_base = seglist.seglist_base_seq;
        }
    }

    return flushed;
}

// we are on a FIN, the data has been scanned, it has no gaps,
// but somehow we are waiting for more data - do final flush here
// FIXIT-M this convoluted expression needs some refactoring to simplify
bool TcpReassembler::final_flush_on_fin(int32_t flush_amt, Packet *p, FinSeqNumStatus fin_status)
{
    return tracker.fin_seq_status >= fin_status
        && -1 <= flush_amt && flush_amt <= 0
        && paf.state == StreamSplitter::SEARCH
        && !p->flow->searching_for_service();
}

bool TcpReassembler::asymmetric_flow_flushed(uint32_t flushed, snort::Packet *p)
{
    bool asymmetric = flushed && seglist.seg_count && !p->flow->two_way_traffic() && !p->ptrs.tcph->is_syn();
    if ( asymmetric )
    {
        TcpStreamTracker::TcpState peer = tracker.session->get_peer_state(tracker);
        asymmetric = ( peer == TcpStreamTracker::TCP_SYN_SENT || peer == TcpStreamTracker::TCP_SYN_RECV
            || peer == TcpStreamTracker::TCP_MID_STREAM_SENT );
    }

    return asymmetric;
}

// define a tracker to assign to the Ignore Flush Policy reassembler and
// create an instance of the Ignore reassembler.  When reassembly is ignored
// all operations are no-ops so a single instance is created and shared by
// all TCP sessions with a flush policy of ignore.  Minimal initialization
// is performed as no state or processing is done by this reassembler.
// The ignore tracker reassembler member variable is set to the ignore
// reassembler as it is referenced in the dtor of the tracker.  The ignore
// tracker is never assigned or used by a Flow, it's only purpose is to
// be passed into the ignore reassembler (along with the tracker's seglist)
TcpStreamTracker ignore_tracker(false);
TcpReassemblerIgnore* tcp_ignore_reassembler = new TcpReassemblerIgnore();

TcpReassemblerIgnore::TcpReassemblerIgnore()
    : TcpReassembler(ignore_tracker, ignore_tracker.seglist)
{
    tracker.reassembler = this;
}

uint32_t TcpReassemblerIgnore::perform_partial_flush(snort::Flow* flow, snort::Packet*& p)
{
    p = get_packet(flow, packet_dir, server_side);
    return 0;
}

