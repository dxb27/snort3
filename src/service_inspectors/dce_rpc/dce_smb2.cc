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

// SMB2 file processing
// Author(s):  Hui Cao <huica@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_smb2.h"

#include "flow/flow_key.h"
#include "stream/stream.h"

#include "dce_smb2_commands.h"

using namespace snort;

const char* smb2_command_string[SMB2_COM_MAX] = {
    "SMB2_COM_NEGOTIATE",
    "SMB2_COM_SESSION_SETUP",
    "SMB2_COM_LOGOFF",
    "SMB2_COM_TREE_CONNECT",
    "SMB2_COM_TREE_DISCONNECT",
    "SMB2_COM_CREATE",
    "SMB2_COM_CLOSE",
    "SMB2_COM_FLUSH",
    "SMB2_COM_READ",
    "SMB2_COM_WRITE",
    "SMB2_COM_LOCK",
    "SMB2_COM_IOCTL",
    "SMB2_COM_CANCEL",
    "SMB2_COM_ECHO",
    "SMB2_COM_QUERY_DIRECTORY",
    "SMB2_COM_CHANGE_NOTIFY",
    "SMB2_COM_QUERY_INFO",
    "SMB2_COM_SET_INFO",
    "SMB2_COM_OPLOCK_BREAK" };

DCE2_Smb2RequestTracker::DCE2_Smb2RequestTracker(uint64_t file_id_v,
    uint64_t offset_v) :   file_id(file_id_v), offset(offset_v)
{
    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL,
        GET_CURRENT_PACKET, "Request tracker created with file_id = 0x%" PRIx64 " offset = %" PRIu64 "\n", file_id,
        offset);
}

DCE2_Smb2RequestTracker::DCE2_Smb2RequestTracker(char* fname_v,
    uint16_t fname_len_v) :   fname(fname_v), fname_len(fname_len_v)
{
    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL,
        GET_CURRENT_PACKET, "Request tracker created\n");
}

DCE2_Smb2RequestTracker::~DCE2_Smb2RequestTracker()
{
    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL,
        nullptr, "Request tracker terminating\n");
    if (fname)
        snort_free(fname);
}

DCE2_Smb2FileTracker::DCE2_Smb2FileTracker(uint64_t file_id_v, DCE2_Smb2TreeTracker* ttr_v,
    DCE2_Smb2SessionTracker* str_v, Flow* flow_v) :   file_id(file_id_v), ttr(ttr_v),
    str(str_v), parent_flow(flow_v), ignore(false), upload(false), multi_channel_file(false)
{
    dce2_smb_stats.v2_total_file_trackers++;
    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL,
        GET_CURRENT_PACKET, "File tracker 0x%" PRIx64 " created\n", file_id);
    str->update_cache_size(sizeof(DCE2_Smb2FileTracker));
}

DCE2_Smb2FileTracker::~DCE2_Smb2FileTracker(void)
{
    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL,
        nullptr, "File tracker with file id: 0x%" PRIx64 " tracker terminating\n", file_id);
    auto all_conn_trackers = str->conn_trackers.get_all_entry();
    for ( const auto& h : all_conn_trackers )
    {
        if (h.second->ftracker_tcp)
        {
<<<<<<< HEAD
            if (h.second->ftracker_tcp == this)
=======
            return;
        }
    }

    DCE2_ListInsert(ssd->tids, (void*)(uintptr_t)tid, (void*)(uintptr_t)share_type);
}

static DCE2_Ret DCE2_Smb2FindTid(DCE2_SmbSsnData* ssd, const Smb2Hdr* smb_hdr)
{
    /* Still process async commands*/
    if (alignedNtohl(&(smb_hdr->flags)) & SMB2_FLAGS_ASYNC_COMMAND)
        return DCE2_RET__SUCCESS;

    return DCE2_ListFindKey(ssd->tids, (void*)(uintptr_t)Smb2Tid(smb_hdr));
}

static inline void DCE2_Smb2RemoveTid(DCE2_SmbSsnData* ssd, const uint32_t tid)
{
    DCE2_ListRemove(ssd->tids, (void*)(uintptr_t)tid);
}

static inline void DCE2_Smb2StoreRequest(DCE2_SmbSsnData* ssd,
    uint64_t message_id, uint64_t offset, uint64_t file_id)
{
    Smb2Request* request = ssd->smb2_requests;
    ssd->max_outstanding_requests = 128; /* windows client max */

    while (request)
    {
        if (request->message_id == message_id)
            return;
        request = request->next;
    }

    request = (Smb2Request*)snort_calloc(sizeof(*request));

    ssd->outstanding_requests++;

    if (ssd->outstanding_requests >= ssd->max_outstanding_requests)
    {
        dce_alert(GID_DCE2, DCE2_SMB_MAX_REQS_EXCEEDED, (dce2CommonStats*)&dce2_smb_stats);
        snort_free((void*)request);
        return;
    }

    request->message_id = message_id;
    request->offset = offset;
    request->file_id = file_id;

    request->next = ssd->smb2_requests;
    request->previous = nullptr;
    if (ssd->smb2_requests)
        ssd->smb2_requests->previous = request;
    ssd->smb2_requests = request;
}

static inline Smb2Request* DCE2_Smb2GetRequest(DCE2_SmbSsnData* ssd,
    uint64_t message_id)
{
    Smb2Request* request = ssd->smb2_requests;
    while (request)
    {
        if (request->message_id == message_id)
            return request;
        request = request->next;
    }

    return nullptr;
}

static inline void DCE2_Smb2RemoveRequest(DCE2_SmbSsnData* ssd,
    Smb2Request* request)
{
    if (request->previous)
    {
        request->previous->next = request->next;
    }

    if (request->next)
    {
        request->next->previous = request->previous;
    }

    if (request == ssd->smb2_requests)
    {
        ssd->smb2_requests =  request->next;
    }

    ssd->outstanding_requests--;
    snort_free((void*)request);
}

static inline void DCE2_Smb2FreeFileName(DCE2_SmbFileTracker* ftracker)
{
    if (ftracker->file_name)
    {
        snort_free((void*)ftracker->file_name);
        ftracker->file_name = nullptr;
    }
    ftracker->file_name_size = 0;
}

static inline void DCE2_Smb2ResetFileName(DCE2_SmbFileTracker* ftracker)
{
    // FIXIT-L remove snort_free once file cache is ported.
    if (ftracker->file_name)
    {
        snort_free((void*)ftracker->file_name);
    }
    ftracker->file_name = nullptr;
    ftracker->file_name_size = 0;
}

static inline FileContext* get_file_context(DCE2_SmbSsnData* ssd, uint64_t file_id)
{
    assert(ssd->sd.wire_pkt);
    FileFlows* file_flows = FileFlows::get_file_flows((ssd->sd.wire_pkt)->flow);
    assert(file_flows);
    return file_flows->get_file_context(file_id, true);
}

static inline void DCE2_Smb2ProcessFileData(DCE2_SmbSsnData* ssd, const uint8_t* file_data,
    uint32_t data_size, FileDirection dir)
{
    int64_t file_detection_depth = DCE2_ScSmbFileDepth((dce2SmbProtoConf*)ssd->sd.config);
    int64_t detection_size = 0;

    if (file_detection_depth == 0)
        detection_size = data_size;
    else if ( ssd->ftracker.tracker.file.file_offset < (uint64_t)file_detection_depth)
    {
        if ( file_detection_depth - ssd->ftracker.tracker.file.file_offset < data_size )
            detection_size = file_detection_depth - ssd->ftracker.tracker.file.file_offset;
        else
            detection_size = data_size;
    }

    if (detection_size)
    {
        set_file_data(file_data,
            (detection_size > UINT16_MAX) ? UINT16_MAX : (uint16_t)detection_size);

        DCE2_FileDetect();
    }

    assert(ssd->sd.wire_pkt);
    FileFlows* file_flows = FileFlows::get_file_flows((ssd->sd.wire_pkt)->flow);

    file_flows->file_process(ssd->ftracker.fid_v2, file_data, data_size,
        ssd->ftracker.tracker.file.file_offset, dir);
}

/********************************************************************
 *
 * Process tree connect command
 * Share type is defined here
 *
 ********************************************************************/
static void DCE2_Smb2TreeConnect(DCE2_SmbSsnData* ssd, const Smb2Hdr* smb_hdr,
    uint8_t* smb_data, const uint8_t* end)
{
    /* Using structure size to decide whether it is response or request*/
    uint16_t structure_size;
    Smb2TreeConnectResponseHdr* smb_tree_connect_hdr = (Smb2TreeConnectResponseHdr*)smb_data;

    if ((const uint8_t*)smb_tree_connect_hdr + SMB2_TREE_CONNECT_RESPONSE_STRUC_SIZE > end)
        return;

    structure_size = alignedNtohs(&(smb_tree_connect_hdr->structure_size));

    if (structure_size == SMB2_TREE_CONNECT_RESPONSE_STRUC_SIZE)
    {
        DCE2_Smb2InsertTid(ssd, Smb2Tid(smb_hdr), smb_tree_connect_hdr->share_type);
    }
}

/********************************************************************
 *
 * Process tree connect command
 * Share type is defined here
 *
 ********************************************************************/
static void DCE2_Smb2TreeDisconnect(DCE2_SmbSsnData* ssd, const Smb2Hdr* smb_hdr,
    uint8_t* smb_data, const uint8_t* end)
{
    /* Using structure size to decide whether it is response or request*/
    uint16_t structure_size;
    Smb2TreeDisConnectHdr* smb_tree_disconnect_hdr = (Smb2TreeDisConnectHdr*)smb_data;

    if ((const uint8_t*)smb_tree_disconnect_hdr + SMB2_TREE_DISCONNECT_STRUC_SIZE > end)
        return;

    structure_size = alignedNtohs(&(smb_tree_disconnect_hdr->structure_size));

    if (structure_size == SMB2_TREE_DISCONNECT_STRUC_SIZE)
    {
        DCE2_Smb2RemoveTid(ssd, Smb2Tid(smb_hdr));
    }
}

/********************************************************************
 *
 * Process create request, first command for a file processing
 * Update file name
 *
 ********************************************************************/
static void DCE2_Smb2CreateRequest(DCE2_SmbSsnData* ssd, const Smb2Hdr*,
    Smb2CreateRequestHdr* smb_create_hdr,const uint8_t* end)
{
    uint16_t name_offset = alignedNtohs(&(smb_create_hdr->name_offset));
    DebugMessage(DEBUG_DCE_SMB, "Processing create request command!\n");
    DCE2_Smb2InitFileTracker(&ssd->ftracker, false, 0);

    if (name_offset > SMB2_HEADER_LENGTH)
    {
        uint16_t size;
        uint8_t* file_data =  (uint8_t*)smb_create_hdr + smb_create_hdr->name_offset -
            SMB2_HEADER_LENGTH;
        if (file_data >= end)
            return;
        size = alignedNtohs(&(smb_create_hdr->name_length));
        if (!size || (file_data + size > end))
            return;
        if (ssd->ftracker.file_name)
        {
            snort_free((void*)ssd->ftracker.file_name);
        }
        ssd->ftracker.file_name = DCE2_Smb2GetFileName(file_data, size, true, false);
        if (ssd->ftracker.file_name)
            ssd->ftracker.file_name_size = strlen(ssd->ftracker.file_name);
    }
}

/********************************************************************
 *
 * Process create response, need to update file id
 * For downloading, file size is decided here
 *
 ********************************************************************/
static void DCE2_Smb2CreateResponse(DCE2_SmbSsnData* ssd, const Smb2Hdr*,
    Smb2CreateResponseHdr* smb_create_hdr, const uint8_t*)
{
    uint64_t fileId_persistent;
    uint64_t file_size = UNKNOWN_FILE_SIZE;
    DebugMessage(DEBUG_DCE_SMB, "Processing create response command!\n");

    fileId_persistent = alignedNtohq((const uint64_t*)(&(smb_create_hdr->fileId_persistent)));
    ssd->ftracker.fid_v2 = fileId_persistent;
    if (smb_create_hdr->end_of_file)
    {
        file_size = alignedNtohq((const uint64_t*)(&(smb_create_hdr->end_of_file)));
        DebugFormat(DEBUG_DCE_SMB, "Get file size %" PRIu64 "!\n", file_size);
        ssd->ftracker.tracker.file.file_size = file_size;
    }

    if (ssd->ftracker.file_name && ssd->ftracker.file_name_size)
    {
        FileContext* file = get_file_context(ssd, ssd->ftracker.fid_v2);
        if (file)
        {
            file->set_file_size(file_size);
            file->set_file_name(ssd->ftracker.file_name, ssd->ftracker.file_name_size);
        }
    }
    DCE2_Smb2ResetFileName(&(ssd->ftracker));
}

/********************************************************************
 *
 * Process create command
 *
 ********************************************************************/
static void DCE2_Smb2Create(DCE2_SmbSsnData* ssd, const Smb2Hdr* smb_hdr,
    uint8_t* smb_data, const uint8_t* end)
{
    uint16_t structure_size;
    Smb2CreateRequestHdr* smb_create_hdr = (Smb2CreateRequestHdr*)smb_data;

    structure_size = alignedNtohs(&(smb_create_hdr->structure_size));

    /* Using structure size to decide whether it is response or request */
    if (structure_size == SMB2_CREATE_REQUEST_STRUC_SIZE)
    {
        if ((const uint8_t*)smb_create_hdr + SMB2_CREATE_REQUEST_STRUC_SIZE - 1 > end)
            return;
        DCE2_Smb2CreateRequest(ssd, smb_hdr, (Smb2CreateRequestHdr*)smb_create_hdr, end);
    }
    else if (structure_size == SMB2_CREATE_RESPONSE_STRUC_SIZE)
    {
        if ((const uint8_t*)smb_create_hdr + SMB2_CREATE_RESPONSE_STRUC_SIZE -1 > end)
            return;
        DCE2_Smb2CreateResponse(ssd, smb_hdr, (Smb2CreateResponseHdr*)smb_create_hdr, end);
    }
    else if (structure_size == SMB2_ERROR_RESPONSE_STRUC_SIZE)
    {
        Smb2ErrorResponseHdr* smb_err_response_hdr = (Smb2ErrorResponseHdr*)smb_data;
        if ((const uint8_t*)smb_create_hdr + SMB2_ERROR_RESPONSE_STRUC_SIZE - 1 > end)
            return;
        /* client will ignore when byte count is 0 */
        if (smb_err_response_hdr->byte_count)
        {
            /*Response error, clean up request state*/
            DCE2_Smb2FreeFileName(&(ssd->ftracker));
        }
    }
    else
    {
        DebugMessage(DEBUG_DCE_SMB, "Wrong format for smb create command!\n");
    }
}

/********************************************************************
 *
 * Process close command
 * For some upload, file_size is decided here.
 *
 ********************************************************************/
static void DCE2_Smb2CloseCmd(DCE2_SmbSsnData* ssd, const Smb2Hdr*,
    uint8_t* smb_data, const uint8_t* end)
{
    /* Using structure size to decide whether it is response or request*/
    uint16_t structure_size;
    Smb2CloseRequestHdr* smb_close_hdr = (Smb2CloseRequestHdr*)smb_data;

    if ((const uint8_t*)smb_close_hdr + SMB2_CLOSE_REQUEST_STRUC_SIZE > end)
        return;

    structure_size = alignedNtohs(&(smb_close_hdr->structure_size));

    if ((structure_size == SMB2_CLOSE_REQUEST_STRUC_SIZE) &&
        !ssd->ftracker.tracker.file.file_size
        && ssd->ftracker.tracker.file.file_offset)
    {
        FileDirection dir = DCE2_SsnFromClient(ssd->sd.wire_pkt) ? FILE_UPLOAD : FILE_DOWNLOAD;
        ssd->ftracker.tracker.file.file_size = ssd->ftracker.tracker.file.file_offset;
        uint64_t fileId_persistent = alignedNtohq(&(smb_close_hdr->fileId_persistent));
        FileContext* file = get_file_context(ssd, fileId_persistent);
        if (file)
        {
            file->set_file_size(ssd->ftracker.tracker.file.file_size);
        }

        DCE2_Smb2ProcessFileData(ssd, nullptr, 0, dir);
    }
}

/********************************************************************
 *
 * Process set info command
 * For upload, file_size is decided here.
 *
 ********************************************************************/
static void DCE2_Smb2SetInfo(DCE2_SmbSsnData* ssd, const Smb2Hdr*,
    uint8_t* smb_data, const uint8_t* end)
{
    /* Using structure size to decide whether it is response or request*/
    uint16_t structure_size;
    Smb2SetInfoRequestHdr* smb_set_info_hdr = (Smb2SetInfoRequestHdr*)smb_data;

    if ((const uint8_t*)smb_set_info_hdr + SMB2_SET_INFO_REQUEST_STRUC_SIZE > end)
        return;

    structure_size = alignedNtohs(&(smb_set_info_hdr->structure_size));

    if (structure_size == SMB2_SET_INFO_REQUEST_STRUC_SIZE)
    {
        uint8_t* file_data =  (uint8_t*)smb_set_info_hdr + SMB2_SET_INFO_REQUEST_STRUC_SIZE - 1;
        if (smb_set_info_hdr->file_info_class == SMB2_FILE_ENDOFFILE_INFO)
        {
            uint64_t file_size = alignedNtohq((const uint64_t*)file_data);
            DebugFormat(DEBUG_DCE_SMB, "Get file size %" PRIu64 "!\n", file_size);
            ssd->ftracker.tracker.file.file_size = file_size;
            uint64_t fileId_persistent = alignedNtohq(&(smb_set_info_hdr->fileId_persistent));
            FileContext* file = get_file_context(ssd, fileId_persistent);
            if (file)
>>>>>>> offload
            {
                h.second->ftracker_tcp = nullptr;
                h.second->ftracker_local = nullptr;
            }
        }
    }
    if (multi_channel_file)
        dce2_smb_stats.v2_mc_file_transfers++;
    if (co_tracker != nullptr)
    {
        DCE2_CoCleanTracker(co_tracker);
        snort_free((void*)co_tracker);
    }
    str->update_cache_size(-(int)sizeof(DCE2_Smb2FileTracker));
}

DCE2_Smb2TreeTracker::DCE2_Smb2TreeTracker (uint32_t tid_v, uint8_t share_type_v) :
    share_type(share_type_v), tid(tid_v)
{
    dce2_smb_stats.v2_total_tree_trackers++;
    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL,
        GET_CURRENT_PACKET, "Tree tracker %" PRIu32 " created\n", tid);
}

DCE2_Smb2TreeTracker::~DCE2_Smb2TreeTracker(void)
{
    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL,
        nullptr, "Tree tracker %" PRIu32 " terminating\n", tid);
}

DCE2_Smb2SessionTracker::DCE2_Smb2SessionTracker(uint64_t sid) :   conn_trackers(false), session_id(sid),
    encryption_flag(0)
{
    update_cache_size((int)sizeof(DCE2_Smb2SessionTracker));
    dce2_smb_stats.v2_total_session_trackers++;
    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL,
        GET_CURRENT_PACKET, "Session tracker 0x%" PRIx64 " created\n", session_id);
}

DCE2_Smb2SessionTracker::~DCE2_Smb2SessionTracker(void)
{
    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL,
        nullptr, "Session tracker 0x%" PRIx64 " terminating\n", session_id);
    removeSessionFromAllConnection();
    auto all_tree_trackers = tree_trackers.get_all_entry();
    for ( const auto& h : all_tree_trackers )
    {
        removeTtracker(h.first);
    }
    update_cache_size(-(int)sizeof(DCE2_Smb2SessionTracker));
}

void DCE2_Smb2SessionTracker::removeSessionFromAllConnection()
{
    auto all_conn_trackers = conn_trackers.get_all_entry();
    auto all_tree_trackers = tree_trackers.get_all_entry();
    for ( auto& h : all_conn_trackers )
    {
        if (h.second->ftracker_tcp)
        {
            for (auto& t : all_tree_trackers)
            {
                DCE2_Smb2FileTracker* ftr = t.second->findFtracker(
                    h.second->ftracker_tcp->file_id);
                if (ftr and ftr == h.second->ftracker_tcp)
                {
                    h.second->ftracker_tcp = nullptr;
                    h.second->ftracker_local = nullptr;
                    break;
                }
            }
        }
        DCE2_Smb2RemoveSidInSsd(h.second, session_id);
    }
}

void DCE2_Smb2SessionTracker::update_cache_size(int size)
{
    DCE2_SmbSessionCacheUpdateSize(size);
}

DCE2_Smb2SsnData::DCE2_Smb2SsnData()
{
    Packet* p = DetectionEngine::get_current_packet();
    memset(&sd, 0, sizeof(DCE2_SsnData));
    memset(&policy, 0, sizeof(DCE2_Policy));
    dialect_index = 0;
    ssn_state_flags = 0;
    ftracker_tcp = nullptr;
    smb_id = 0;
    max_file_depth = FileService::get_max_file_depth();
    max_outstanding_requests = 10;  // Until Negotiate
    flow = p->flow;
    SmbKeyHash hasher;
    flow_key = hasher(*flow->key);
}

DCE2_Smb2SsnData::~DCE2_Smb2SsnData()
{
    for (auto it = session_trackers.cbegin(), next_it = it; it != session_trackers.cend(); it = next_it)
    {
        ++next_it;
        auto sptr = it->second.lock();
        if (sptr)
        {
            if (flow_key)
                sptr->removeConnectionTracker(flow_key); // remove tcp connection from session
                                                         // tracker
            auto ttrs = sptr->tree_trackers.get_all_entry();
            for (const auto& titer: ttrs)
            {
                DCE2_Smb2TreeTracker* ttr = titer.second;
                auto ftrs = ttr->file_trackers.get_all_entry();
                for (const auto& fiter: ftrs)
                {
                    DCE2_Smb2FileTracker* ftr = fiter.second;
                    if (flow == ftr->parent_flow)
                        ftr->parent_flow = nullptr;
                }
            }
        }
    }
}

void DCE2_Smb2SsnData::set_reassembled_data(uint8_t* nb_ptr, uint16_t co_len)
{
    NbssHdr* nb_hdr = (NbssHdr*)nb_ptr;
    SmbNtHdr* smb_hdr = (SmbNtHdr*)((uint8_t*)nb_hdr + sizeof(NbssHdr));

    uint32_t tid = (ftracker_tcp) ? ftracker_tcp->ttr->get_tid() : 0;
    smb_hdr->smb_tid = alignedNtohl((const uint32_t*)&tid);

    if (DetectionEngine::get_current_packet()->is_from_client())
    {
        Smb2WriteRequestHdr* write = (Smb2WriteRequestHdr*)((uint8_t*)smb_hdr + sizeof(SmbNtHdr));
        uint32_t nb_len = sizeof(SmbNtHdr) + sizeof(Smb2WriteRequestHdr) + co_len;

        if (nb_len > UINT16_MAX)
            nb_len = UINT16_MAX;
        write->structure_size = SMB2_WRITE_REQUEST_STRUC_SIZE;
        nb_hdr->length = htons((uint16_t)nb_len);
        if (ftracker_tcp)
        {
            uint64_t fid = ftracker_tcp->file_id;
            write->fileId_persistent = alignedNtohq(&fid);
            write->fileId_volatile = alignedNtohq(&fid);
        }
        else
            write->fileId_persistent = write->fileId_volatile = 0;
        write->length = alignedNtohs(&co_len);
    }
    else
    {
        Smb2ReadResponseHdr* read = (Smb2ReadResponseHdr*)((uint8_t*)smb_hdr + sizeof(SmbNtHdr));
        uint32_t nb_len = sizeof(SmbNtHdr) + sizeof(Smb2ReadResponseHdr) + co_len;

        if (nb_len > UINT16_MAX)
            nb_len = UINT16_MAX;

        nb_hdr->length = htons((uint16_t)nb_len);
        read->structure_size = SMB2_READ_RESPONSE_STRUC_SIZE;
        read->length = alignedNtohs(&co_len);
    }
}

static inline bool DCE2_Smb2FindSidTid(DCE2_Smb2SsnData* ssd, const uint64_t sid,
    const uint32_t tid, const uint32_t mid, DCE2_Smb2SessionTracker** str, DCE2_Smb2TreeTracker** ttr, bool
    lookup_cache = false)
{
    *str = DCE2_Smb2FindSidInSsd(ssd, sid).get();
    if (!*str)
    {
        if (lookup_cache)
            *str = DCE2_Smb2FindElseCreateSid(ssd, sid, false);
    }
    if (!*str)
        return false;

    if (!tid)
        *ttr = ssd->GetTreeTrackerFromMessage(mid);
    else
        *ttr = (*str)->findTtracker(tid);

    if (!*ttr)
        return false;

    return true;
}

// FIXIT-L port fileCache related code along with
// DCE2_Smb2Init, DCE2_Smb2Close and DCE2_Smb2UpdateStats

static void DCE2_Smb2Inspect(DCE2_Smb2SsnData* ssd, const Smb2Hdr* smb_hdr,
    const uint8_t* end)
{
    const uint8_t* smb_data = (const uint8_t*)smb_hdr + SMB2_HEADER_LENGTH;
    uint16_t command = alignedNtohs(&(smb_hdr->command));
    int16_t structure_size = alignedNtohs((const uint16_t*)smb_data);
    DCE2_Smb2SessionTracker* str = nullptr;
    DCE2_Smb2TreeTracker* ttr = nullptr;
    uint32_t tid = 0;

    uint64_t mid = Smb2Mid(smb_hdr);
    uint64_t sid = Smb2Sid(smb_hdr);
    /* Still process async commands*/
    if (!(alignedNtohl(&(smb_hdr->flags)) & SMB2_FLAGS_ASYNC_COMMAND))
        tid = Smb2Tid(smb_hdr);

    SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL,
        DetectionEngine::get_current_packet(),
        "%s : mid %" PRIu64 " sid 0x%" PRIx64 " tid %" PRIu32 "\n",
        (command <= SMB2_COM_OPLOCK_BREAK ? smb2_command_string[command] : "unknown"),
        mid, sid, tid);
    switch (command)
    {
    case SMB2_COM_NEGOTIATE:
        if (structure_size == SMB2_NEGOTIATE_RESPONSE_STRUC_SIZE)
        {
            const Smb2NegotiateResponseHdr* neg_resp_hdr = (const
                Smb2NegotiateResponseHdr*)smb_data;
            if (neg_resp_hdr->capabilities & SMB2_GLOBAL_CAP_MULTI_CHANNEL)
            {
                //total multichannel sessions
                dce2_smb_stats.total_mc_sessions++;
            }
        }
        break;
    case SMB2_COM_CREATE:
        if (!tid)
        {
            //Check request tracker for tid in Async case.
            auto rtracker = ssd->findRtracker(mid);
            if (rtracker)
                tid = rtracker->get_tree_id();
        }
        dce2_smb_stats.v2_crt++;
        DCE2_Smb2Create(ssd, smb_hdr, smb_data, end, mid, sid, tid);
        break;
    case SMB2_COM_READ:
        if (!tid)
        {
            //Check request tracker for tid in Async case.
            auto rtracker = ssd->findRtracker(mid);
            if (rtracker)
                tid = rtracker->get_tree_id();
        }
        dce2_smb_stats.v2_read++;
        if (!DCE2_Smb2FindSidTid(ssd, sid, tid, mid, &str, &ttr, true))
        {
            dce2_smb_stats.v2_read_ignored++;
            return;
        }

        DCE2_Smb2Read(ssd, smb_hdr, smb_data, end, str, ttr, mid);
        break;
    case SMB2_COM_WRITE:
        if (!tid)
        {
            //Check request tracker for tid in Async case.
            auto rtracker = ssd->findRtracker(mid);
            if (rtracker)
                tid = rtracker->get_tree_id();
        }
        dce2_smb_stats.v2_wrt++;
        if (!DCE2_Smb2FindSidTid(ssd, sid, tid, mid, &str, &ttr, true))
        {
            dce2_smb_stats.v2_wrt_ignored++;
            return;
        }

        DCE2_Smb2Write(ssd, smb_hdr, smb_data, end, str, ttr, mid);
        break;
    case SMB2_COM_SET_INFO:
        if (!tid)
        {
            //Check request tracker for tid in Async case.
            auto rtracker = ssd->findRtracker(mid);
            if (rtracker)
                tid = rtracker->get_tree_id();
        }
        dce2_smb_stats.v2_setinfo++;
        if (!DCE2_Smb2FindSidTid(ssd, sid, tid, mid, &str, &ttr))
        {
            dce2_smb_stats.v2_stinf_ignored++;
            return;
        }

        DCE2_Smb2SetInfo(ssd, smb_hdr, smb_data, end, ttr);
        break;
    case SMB2_COM_CLOSE:
        if (!tid)
        {
            //Check request tracker for tid in Async case.
            auto rtracker = ssd->findRtracker(mid);
            if (rtracker)
                tid = rtracker->get_tree_id();
        }
        dce2_smb_stats.v2_cls++;
        if (!DCE2_Smb2FindSidTid(ssd, sid, tid, mid, &str, &ttr))
        {
            dce2_smb_stats.v2_cls_ignored++;
            return;
        }

        DCE2_Smb2CloseCmd(ssd, smb_hdr, smb_data, end, ttr, str, mid);
        break;
    case SMB2_COM_TREE_CONNECT:
        dce2_smb_stats.v2_tree_cnct++;
        // This will always return session tracker
        str = DCE2_Smb2FindElseCreateSid(ssd, sid, true);
        if (str)
        {
            DCE2_Smb2TreeConnect(ssd, smb_hdr, smb_data, end, str, tid);
        }
        break;
    case SMB2_COM_TREE_DISCONNECT:
        dce2_smb_stats.v2_tree_discn++;
        if (!DCE2_Smb2FindSidTid(ssd, sid, tid, mid, &str, &ttr))
        {
            dce2_smb_stats.v2_tree_discn_ignored++;
            return;
        }
        DCE2_Smb2TreeDisconnect(ssd, smb_data, end);
        break;
    case SMB2_COM_SESSION_SETUP:
        dce2_smb_stats.v2_setup++;
        DCE2_Smb2Setup(ssd, smb_hdr, sid, smb_data, end);
        break;
    case SMB2_COM_LOGOFF:
        dce2_smb_stats.v2_logoff++;
        DCE2_Smb2Logoff(ssd, smb_data, sid);
        break;
    case SMB2_COM_IOCTL:
        if (!tid)
        {
            //Check request tracker for tid in Async case.
            auto rtracker = ssd->findRtracker(mid);
            if (rtracker)
                tid = rtracker->get_tree_id();
        }
        if (!DCE2_Smb2FindSidTid(ssd, sid, tid, mid, &str, &ttr))
        {
            dce2_smb_stats.v2_ioctl_ignored++;
            return;
        }
        else if (SMB2_SHARE_TYPE_DISK != ttr->get_share_type())
        {
            dce2_smb_stats.v2_ioctl++;
            DCE2_Smb2IoctlCommand(ssd, smb_hdr, smb_data, end, str, ttr, mid);
        }
        else
        {
            dce2_smb_stats.v2_ioctl_ignored++;
            return;
        }
        break;
    default:
        dce2_smb_stats.v2_msgs_uninspected++;
        break;
    }
}

// This is the main entry point for SMB2 processing.
void DCE2_Smb2Process(DCE2_Smb2SsnData* ssd)
{
    Packet* p = DetectionEngine::get_current_packet();
    const uint8_t* data_ptr = p->data;
    uint16_t data_len = p->dsize;
<<<<<<< HEAD
    // Process the header
    if (p->is_pdu_start())
    {
        // Check header length
        if (data_len < sizeof(NbssHdr) + SMB2_HEADER_LENGTH)
=======

    if (!FileService::is_file_service_enabled())
        return;

    /*Check header length*/
    if (data_len < sizeof(NbssHdr) + SMB2_HEADER_LENGTH)
        return;

    if (!ssd->ftracker.is_smb2)
    {
        DCE2_Smb2InitFileTracker(&(ssd->ftracker), 0, 0);
    }

    /* Process the header */
    if (p->is_pdu_start())
    {
        uint32_t next_command_offset;
        Smb2Hdr* smb_hdr = (Smb2Hdr*)(data_ptr + sizeof(NbssHdr));
        next_command_offset = alignedNtohl(&(smb_hdr->next_command));
        if (next_command_offset + sizeof(NbssHdr) > p->dsize)
>>>>>>> offload
        {
            dce2_smb_stats.v2_hdr_err++;
            SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL, p,
                "Header error with data length %d\n",data_len);
            return;
        }
        const Smb2Hdr* smb_hdr = (const Smb2Hdr*)(data_ptr + sizeof(NbssHdr));
        const Smb2TransformHdr* smb_trans_hdr = (const Smb2TransformHdr*)(data_ptr +
            sizeof(NbssHdr));
        uint32_t smb_proto_id = SmbTransformId(smb_trans_hdr);
        uint64_t sid = smb_trans_hdr->session_id;
        if (smb_proto_id == DCE2_SMB2_TRANS_ID)
        {
            SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL,
                p, "Encrypted header is received \n");
            DCE2_Smb2SessionTracker* session = DCE2_Smb2FindElseCreateSid(ssd, sid);
            if (session)
            {
                session->set_encryption_flag(true);
            }
        }
        uint32_t next_command_offset;
        uint8_t compound_request_index = 0;
        // SMB protocol allows multiple smb commands to be grouped in a single packet.
        // So loop through to parse all the smb commands.
        // Reference: https://msdn.microsoft.com/en-us/library/cc246614.aspx
        // "A nonzero value for the NextCommand field in the SMB2 header indicates a compound
        // request. NextCommand in the SMB2 header of a request specifies an offset, in bytes,
        // from the beginning of the SMB2 header under consideration to the start of the 8-byte
        // aligned SMB2 header of the subsequent request. Such compounding can be used to append
        // multiple requests up to the maximum size<88> that is supported by the transport."
        do
        {
            DCE2_Smb2Inspect(ssd, smb_hdr, data_ptr +  data_len);
            // In case of message compounding, find the offset of the next smb command
            next_command_offset = alignedNtohl(&(smb_hdr->next_command));
            if (next_command_offset + (const uint8_t*)smb_hdr > (data_ptr + data_len))
            {
                dce_alert(GID_DCE2, DCE2_SMB_BAD_NEXT_COMMAND_OFFSET,
                    (dce2CommonStats*)&dce2_smb_stats, ssd->sd);
                SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
                    p, "bad next command offset\n");
                dce2_smb_stats.v2_bad_next_cmd_offset++;
                return;
            }
            if (next_command_offset)
            {
                smb_hdr = (const Smb2Hdr*)((const uint8_t*)smb_hdr + next_command_offset);
                compound_request_index++;
            }

            if (compound_request_index > DCE2_ScSmbMaxCompound((dce2SmbProtoConf*)ssd->sd.config))
            {
                dce2_smb_stats.v2_cmpnd_req_lt_crossed++;
                SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
                    p, "compound req limit reached %" PRIu8 "\n",
                    compound_request_index);
                return;
            }
        }
        while (next_command_offset and smb_hdr);
    }
    else if ( ssd->ftracker_tcp and ssd->ftracker_local and (ssd->ftracker_local->smb2_pdu_state ==
        DCE2_SMB_PDU_STATE__RAW_DATA))
    {
        SMB_DEBUG(dce_smb_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL,
            p, "raw data file_name_hash %" PRIu64 " fid 0x%" PRIx64 " dir %s\n",
            ssd->ftracker_tcp->file_name_hash, ssd->ftracker_tcp->file_id,
            ssd->ftracker_tcp->upload ? "upload" : "download");

        if (!DCE2_Smb2ProcessFileData(ssd, data_ptr, data_len))
            return;
    }
}

// Check whether the packet is smb2
DCE2_SmbVersion DCE2_Smb2Version(const Packet* p)
{
    // Only check reassembled SMB2 packet
    if ( p->has_paf_payload() and
        (p->dsize > sizeof(NbssHdr) + DCE2_SMB_ID_SIZE) )     // DCE2_SMB_ID is u32
    {
        const Smb2Hdr* smb_hdr = (const Smb2Hdr*)(p->data + sizeof(NbssHdr));
        uint32_t smb_version_id = SmbId((const SmbNtHdr*)smb_hdr);

        if (smb_version_id == DCE2_SMB_ID)
            return DCE2_SMB_VERSION_1;
        else if (smb_version_id == DCE2_SMB2_ID)
            return DCE2_SMB_VERSION_2;
    }

    return DCE2_SMB_VERSION_NULL;
}

