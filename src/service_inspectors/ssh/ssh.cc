//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2004-2013 Sourcefire, Inc.
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

/*
 * SSH inspector
 * Author: Chris Sherwin
 * Contributors: Adam Keeton, Ryan Jordan
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ssh.h"

#include "detection/detection_engine.h"
<<<<<<< HEAD
=======
#include "events/event_queue.h"
>>>>>>> offload
#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "pub_sub/ssh_events.h"
#include "stream/stream.h"

#include "ssh_module.h"
#include "ssh_splitter.h"

using namespace snort;

THREAD_LOCAL ProfileStats sshPerfStats;
THREAD_LOCAL SshStats sshstats;

static unsigned pub_id = 0;

/*
 * Function prototype(s)
 */
static void snort_ssh(SSH_PROTO_CONF* GlobalConf, Packet* p);
static bool process_ssh_version_string(SSH_PROTO_CONF* config, SSHData* sessionp, Packet* p, uint8_t direction);
static bool process_ssh1_key_exchange(SSHData *sessionp, Packet *p, uint8_t direction);
static bool process_ssh2_kexinit(SSHData *sessionp, Packet *p, uint8_t direction);
static bool process_ssh2_key_exchange(SSHData *sessionp, Packet *p, uint8_t direction);
bool is_us_ascii(const char *str, uint16_t size);

unsigned SshFlowData::inspector_id = 0;

SshFlowData::SshFlowData() : FlowData(inspector_id)
{
    sshstats.concurrent_sessions++;
    if (sshstats.max_concurrent_sessions < sshstats.concurrent_sessions)
        sshstats.max_concurrent_sessions = sshstats.concurrent_sessions;
}

SshFlowData::~SshFlowData()
{
    assert(sshstats.concurrent_sessions > 0);
    sshstats.concurrent_sessions--;
}

SSHData* SetNewSSHData(Packet* p)
{
    SshFlowData* fd = new SshFlowData;
    p->flow->set_flow_data(fd);
    return &fd->session;
}

SSHData* get_session_data(const Flow* flow)
{
    SshFlowData* fd = (SshFlowData*)flow->get_flow_data(SshFlowData::inspector_id);
    return fd ? &fd->session : nullptr;
}

// Main runtime entry point for SSH inspector.
static void snort_ssh(SSH_PROTO_CONF* config, Packet* p)
{
    Profile profile(sshPerfStats);

    // Attempt to get a previously allocated SSH block.
    SSHData* sessp = get_session_data(p->flow);
    if (!sessp)
        return;

    // Don't process if we've missed packets
    if (sessp->state_flags & SSH_FLG_MISSED_PACKETS)
        return;

    // If we picked up mid-stream or missed any packets (midstream pick up
    // means we've already missed packets) set missed packets flag and make
    // sure we don't do any more reassembly on this session
    if ( p->test_session_flags(SSNFLAG_MIDSTREAM)
        or Stream::missed_packets(p->flow, SSN_DIR_BOTH) )
    {
        // Order only matters if the packets are not encrypted
        if ( !(sessp->state_flags & SSH_FLG_SESS_ENCRYPTED ))
        {
            sessp->state_flags |= SSH_FLG_MISSED_PACKETS;
            return;
        }
    }
    sshstats.total_bytes += p->dsize;

    uint8_t direction;
    uint8_t pkt_direction;
    uint32_t search_dir_ver;
    uint32_t search_dir_keyinit;

    // Get the direction of the packet.
    if ( p->is_from_server() )
    {
        direction = SSH_DIR_FROM_SERVER;
        pkt_direction = PKT_FROM_SERVER;
        search_dir_ver = SSH_FLG_SERV_IDSTRING_SEEN;
        search_dir_keyinit = SSH_FLG_SERV_PKEY_SEEN | SSH_FLG_SERV_KEXINIT_SEEN;
    }
    else
    {
        direction = SSH_DIR_FROM_CLIENT;
        pkt_direction = PKT_FROM_CLIENT;
        search_dir_ver = SSH_FLG_CLIENT_IDSTRING_SEEN;
        search_dir_keyinit = SSH_FLG_CLIENT_SKEY_SEEN | SSH_FLG_CLIENT_KEXINIT_SEEN;
    }

    if (!(sessp->state_flags & SSH_FLG_SESS_ENCRYPTED))
    {
        // If server and client have not performed the protocol
        // version exchange yet, must look for version strings.
        if (!(sessp->state_flags & search_dir_ver))
        {
            bool valid_version = process_ssh_version_string(config, sessp, p, direction);
            if (valid_version)
            {
                std::string proto_string((const char *)(p->data), p->dsize);
                SshEvent event(SSH_VERSION_STRING, SSH_NOT_FINISHED, proto_string, pkt_direction, p);
                DataBus::publish(pub_id, SshEventIds::STATE_CHANGE, event, p->flow);
            }
            else
            {
                SshEvent event(SSH_VALIDATION, SSH_INVALID_VERSION, "", pkt_direction, p);
                DataBus::publish(pub_id, SshEventIds::STATE_CHANGE, event, p->flow);
                if (sessp->version == NON_SSH_TRAFFIC)
                    sessp->ssh_aborted = true;
            }
        }
        else if (!(sessp->state_flags & search_dir_keyinit))
        {
            bool keyx_valid = false;
            switch (sessp->version)
            {
            case SSH_VERSION_1:
                keyx_valid = process_ssh1_key_exchange(sessp, p, direction);
                break;
            case SSH_VERSION_2:
                keyx_valid = process_ssh2_kexinit(sessp, p, direction);
                break;
            default:
                // key exchange packet sent before version was determined
                DetectionEngine::queue_event(GID_SSH, SSH_EVENT_VERSION);
                break;
            }
            if (keyx_valid)
            {
                SshEvent event(SSH_VALIDATION, SSH_VALID_KEXINIT, "", pkt_direction, p);
                DataBus::publish(pub_id, SshEventIds::STATE_CHANGE, event, p->flow);
            }
            else
            {
                SshEvent event(SSH_VALIDATION, SSH_INVALID_KEXINIT, "", pkt_direction, p);
                DataBus::publish(pub_id, SshEventIds::STATE_CHANGE, event, p->flow);
                sessp->state_flags |= SSH_FLG_SESS_ENCRYPTED;
            }
        }
        else
        {
            bool keyx_valid = process_ssh2_key_exchange(sessp, p, direction);
            // FIXIT-M
            // Originally, appid only looked at the kexinit packet for validation.
            // We may want to produce an additional event for validation of the
            // entire key exchange.
            if (!keyx_valid)
                sessp->state_flags |= SSH_FLG_SESS_ENCRYPTED;
        }
    }
    else
    {
        // Traffic on this session is currently encrypted.
        // Two of the major SSH exploits, SSH1 CRC-32 and
        // the Challenge-Response Overflow attack occur within
        // the encrypted portion of the SSH session. Therefore,
        // the only way to detect these attacks is by examining
        // amounts of data exchanged for anomalies.
        sessp->num_enc_pkts++;

        if ( sessp->num_enc_pkts <= config->MaxEncryptedPackets )
        {
            if ( direction == SSH_DIR_FROM_CLIENT )
            {
                sessp->num_client_bytes += p->dsize;
                if ( sessp->num_client_bytes >= config->MaxClientBytes )
                {
                    // Probable exploit in progress.
                    if (sessp->version == SSH_VERSION_1)
                        DetectionEngine::queue_event(GID_SSH, SSH_EVENT_CRC32);
<<<<<<< HEAD
=======

>>>>>>> offload
                    else
                        DetectionEngine::queue_event(GID_SSH, SSH_EVENT_RESPOVERFLOW);

                    Stream::stop_inspection(p->flow, p, SSN_DIR_BOTH, -1, 0);
                }
            }
            else
            {
                 // Have seen a server response, so this appears to be a valid
                 // exchange. Reset suspicious byte count to zero
                sessp->num_client_bytes = 0;
            }
        }
        else
        {
            // Have already examined more than the limit
            // of encrypted packets. Both the Gobbles and
            // the CRC32 attacks occur during authentication
            // and therefore cannot be used late in an
            // encrypted session. For performance purposes,
            // stop examining this session.
            Stream::stop_inspection(p->flow, p, SSN_DIR_BOTH, -1, 0);
        }
    }
}

bool is_us_ascii(const char *str, uint16_t size) 
{
    for (uint16_t i = 0, count = 0; i < size; i++) 
    {
        if ((((unsigned char)*str < 32) or (unsigned char)*str > 127) and 
            (((unsigned char)*str != 10 ) and ((unsigned char)*str != 13)))
        {
            if ((count == 0) && (unsigned char)*str == '-')
            {
                count++;
                str++;
                continue;
            }
            return false; 
        }
        str++;
    }
    return true; 
}

static bool process_ssh_version_string(
    SSH_PROTO_CONF* config, SSHData* sessionp, Packet* p, uint8_t direction)
{
    if (p->dsize > config->MaxServerVersionLen)
    {
        DetectionEngine::queue_event(GID_SSH, SSH_EVENT_SECURECRT);
        // SSH_MAX_BANNER_LEN is 255, the maximum specified by the SSH protocol.
        // MaxServerVersionLen defaults to 80,
        // but there may be valid version strings that are longer due to comments.
        if (p->dsize > SSH_MAX_BANNER_LEN)
        {
<<<<<<< HEAD
            return false;
=======
            /* SSH 1.99 which is the same as SSH2.0 */
            version = SSH_VERSION_2;
        }
        else
        {
            version = SSH_VERSION_1;
        }

        /* CAN-2002-0159 */
        /* Verify the version string is not greater than
         * the configured maximum.
         * We've already verified the first 6 bytes, so we'll start
         * check from &version_string[6] */
        /* First make sure the data itself is sufficiently large */
        if ((p->dsize > config->MaxServerVersionLen) &&
            /* CheckStrlen will check if the version string up to
             * MaxServerVersionLen+1 since there's no reason to
             * continue checking after that point*/
            (SSHCheckStrlen(&version_stringp[6], config->MaxServerVersionLen-6)))
        {
            DetectionEngine::queue_event(GID_SSH, SSH_EVENT_SECURECRT);
>>>>>>> offload
        }
    }
    if (p->dsize < SSH_MIN_BANNER_LEN
        or memcmp(p->data, SSH_BANNER, sizeof(SSH_BANNER)-1) != 0)
    {
        // according to the SSH specification,
        // the server can send lines before the version string
        // as long as they don't start with "SSH-",
        // so we will ignore them.
        return true;
    }

    if (!(is_us_ascii((const char*) p->data + 4, p->dsize - 4)))
    {
        sessionp->version = NON_SSH_TRAFFIC;
        return false;
    }

    const char *proto_ver = (const char *)p->data + sizeof(SSH_BANNER) - 1;
    const char *proto_ver_end = (const char *)memchr(proto_ver, '-', p->dsize - sizeof(SSH_BANNER));
    if (!proto_ver_end)
    {
        DetectionEngine::queue_event(GID_SSH, SSH_EVENT_VERSION);
        return false;
    }

    if (proto_ver[0] == '2' and proto_ver[1] == '.')
    {
        sessionp->version = SSH_VERSION_2;
    }
    else if (proto_ver[0] == '1' and proto_ver[1] == '.')
    {
        // version 1.99 == compatibility mode for 2.0
        // determine version from client in this case
        if (direction == SSH_DIR_FROM_CLIENT)
        {
            sessionp->version = SSH_VERSION_1;
        }
        else if (proto_ver[2] != '9' or proto_ver[3] != '9')
        {
            sessionp->version = SSH_VERSION_1;
        }
    }
    else if (((proto_ver[0] >= '3') and (proto_ver[0] <= '9')) and proto_ver[1] == '.')
    {
        DetectionEngine::queue_event(GID_SSH, SSH_EVENT_VERSION);
        sessionp->version = SSH_VERSION_UNKNOWN;
        return false;
    }
    else
    {
        sessionp->version = NON_SSH_TRAFFIC;
        return false;
    }

    /* Saw a valid protocol exchange message. Mark the session
     * according to the direction.
     */
    switch ( direction )
    {
    case SSH_DIR_FROM_SERVER:
        sessionp->state_flags |= SSH_FLG_SERV_IDSTRING_SEEN;
        break;
    case SSH_DIR_FROM_CLIENT:
        sessionp->state_flags |= SSH_FLG_CLIENT_IDSTRING_SEEN;
        break;
    }
    return true;

}

static bool process_ssh1_key_exchange(SSHData *sessionp, Packet *p, uint8_t direction)
{
    if (p->dsize < SSH1_KEYX_MIN_SIZE)
    {
<<<<<<< HEAD
        DetectionEngine::queue_event(GID_SSH, SSH_EVENT_PAYLOAD_SIZE);
        return false;
=======
        uint32_t length;
        uint8_t padding_length;
        uint8_t message_type;

        /*
         * Validate packet data.
         * First 4 bytes should have the SSH packet length,
         * minus any padding.
         */
        if ( dsize < 4 )
        {
            {
                DetectionEngine::queue_event(GID_SSH, SSH_EVENT_PAYLOAD_SIZE);
            }

            return 0;
        }

        /*
         * SSH1 key exchange is very simple and
          * consists of only two messages, a server
         * key and a client key message.`
         */
        memcpy(&length, data, sizeof(length));
        length = ntohl(length);

        /* Packet data should be larger than length, due to padding. */
        if ( dsize < length )
        {
            {
                DetectionEngine::queue_event(GID_SSH, SSH_EVENT_PAYLOAD_SIZE);
            }

            return 0;
        }

        padding_length = (uint8_t)(8 - (length % 8));

        /*
         * With the padding calculated, verify data is sufficiently large
         * to include the message type.
         */
        if ( dsize < (padding_length + 4 + 1 + offset))
        {
            if (offset == 0)
            {
                DetectionEngine::queue_event(GID_SSH, SSH_EVENT_PAYLOAD_SIZE);
            }

            return 0;
        }

        message_type = *( (uint8_t*)(data + padding_length + 4));

        switch ( message_type )
        {
        case SSH_MSG_V1_SMSG_PUBLIC_KEY:
            if ( direction == SSH_DIR_FROM_SERVER )
            {
                sessionp->state_flags |=
                    SSH_FLG_SERV_PKEY_SEEN;
            }
            else
            {
                /* Server msg not from server. */
                DetectionEngine::queue_event(GID_SSH, SSH_EVENT_WRONGDIR);
            }
            break;
        case SSH_MSG_V1_CMSG_SESSION_KEY:
            if ( direction == SSH_DIR_FROM_CLIENT )
            {
                sessionp->state_flags |=
                    SSH_FLG_CLIENT_SKEY_SEEN;
            }
            else
            {
                /* Client msg not from client. */
                DetectionEngine::queue_event(GID_SSH, SSH_EVENT_WRONGDIR);
            }
            break;
        default:
            /* Invalid msg type*/
            break;
        }

        /* Once the V1 key exchange is done, remainder of
         * communications are encrypted.
         */
        ssh_length = length + padding_length + sizeof(length) + offset;

        if ( (sessionp->state_flags & SSH_FLG_V1_KEYEXCH_DONE) ==
            SSH_FLG_V1_KEYEXCH_DONE )
        {
            sessionp->state_flags |= SSH_FLG_SESS_ENCRYPTED;
        }
>>>>>>> offload
    }
    uint32_t payload_length = ntohl(*(const uint32_t *)(p->data));
    uint8_t padding = 8 - (payload_length % 8);
    uint8_t code = p->data[sizeof(uint32_t) + padding];


    if (p->dsize != sizeof(uint32_t) + padding + payload_length
        or p->dsize > SSH_PACKET_MAX_SIZE)
    {
<<<<<<< HEAD
        DetectionEngine::queue_event(GID_SSH, SSH_EVENT_PAYLOAD_SIZE);
        return false;
=======
        /* We want to overlay the data on our data packet struct,
         * so first verify that the data size is big enough.
         * This may legitimately occur such as in the case of a
         * retransmission.
         */
        if ( dsize < sizeof(SSH2Packet) )
        {
            return 0;
        }

        /* Overlay the SSH2 binary data packet struct on the packet */
        ssh2p = (SSH2Packet*)data;
        if ( dsize < SSH2_HEADERLEN + 1)
        {
            /* Invalid packet length. */

            return 0;
        }

        ssh_length = offset + ntohl(ssh2p->packet_length) + sizeof(ssh2p->packet_length);

        switch ( data[SSH2_HEADERLEN] )
        {
        case SSH_MSG_KEXINIT:
            sessionp->state_flags |=
                (direction == SSH_DIR_FROM_SERVER ?
                SSH_FLG_SERV_KEXINIT_SEEN :
                SSH_FLG_CLIENT_KEXINIT_SEEN );
            break;
        default:
            /* Unrecognized message type. */
            break;
        }
    }
    else
    {
        {
            /* Unrecognized version. */
            DetectionEngine::queue_event(GID_SSH, SSH_EVENT_VERSION);
        }

        return 0;
>>>>>>> offload
    }

    switch (code)
    {
    case SSH_MSG_V1_SMSG_PUBLIC_KEY:
        if (direction == SSH_DIR_FROM_SERVER)
        {
<<<<<<< HEAD
            sessionp->state_flags |= SSH_FLG_SERV_PKEY_SEEN;
=======
            if ( sessionp->state_flags & SSH_FLG_SESS_ENCRYPTED )
            {
                return ( npacket_offset + offset );
            }
            {
                /* Invalid packet length. */
                DetectionEngine::queue_event(GID_SSH, SSH_EVENT_PAYLOAD_SIZE);
            }

            return 0;
        }

        switch (data[npacket_offset + SSH2_HEADERLEN] )
        {
        case SSH_MSG_KEXDH_INIT:
            if ( direction == SSH_DIR_FROM_CLIENT )
            {
                sessionp->state_flags |=
                    SSH_FLG_KEXDH_INIT_SEEN;
            }
            else
            {
                /* Client msg from server. */
                DetectionEngine::queue_event(GID_SSH, SSH_EVENT_WRONGDIR);
            }
            break;
        case SSH_MSG_KEXDH_REPLY:
            if ( direction == SSH_DIR_FROM_SERVER )
            {
                /* KEXDH_REPLY has the same msg
                  * type as the new style GEX_REPLY
                 */
                sessionp->state_flags |=
                    SSH_FLG_KEXDH_REPLY_SEEN |
                    SSH_FLG_GEX_REPLY_SEEN;
            }
            else
            {
                /* Server msg from client. */
                DetectionEngine::queue_event(GID_SSH, SSH_EVENT_WRONGDIR);
            }
            break;
        case SSH_MSG_KEXDH_GEX_REQ:
            if ( direction == SSH_DIR_FROM_CLIENT )
            {
                sessionp->state_flags |=
                    SSH_FLG_GEX_REQ_SEEN;
            }
            else
            {
                /* Server msg from client. */
                DetectionEngine::queue_event(GID_SSH, SSH_EVENT_WRONGDIR);
            }
            break;
        case SSH_MSG_KEXDH_GEX_GRP:
            if ( direction == SSH_DIR_FROM_SERVER )
            {
                sessionp->state_flags |=
                    SSH_FLG_GEX_GRP_SEEN;
            }
            else
            {
                /* Client msg from server. */
                DetectionEngine::queue_event(GID_SSH, SSH_EVENT_WRONGDIR);
            }
            break;
        case SSH_MSG_KEXDH_GEX_INIT:
            if ( direction == SSH_DIR_FROM_CLIENT )
            {
                sessionp->state_flags |=
                    SSH_FLG_GEX_INIT_SEEN;
            }
            else
            {
                /* Server msg from client. */
                DetectionEngine::queue_event(GID_SSH, SSH_EVENT_WRONGDIR);
            }
            break;
        case SSH_MSG_NEWKEYS:
            /* This message is required to complete the
             * key exchange. Both server and client should
             * send one, but as per Alex Kirk's note on this,
             * in some implementations the server does not
             * actually send this message. So receving a new
             * keys msg from the client is sufficient.
             */
            if ( direction == SSH_DIR_FROM_CLIENT )
            {
                sessionp->state_flags |= SSH_FLG_NEWKEYS_SEEN;
            }
            break;
        default:
            /* Unrecognized message type. Possibly encrypted */
            sessionp->state_flags |= SSH_FLG_SESS_ENCRYPTED;
            return ( npacket_offset + offset);
        }

        /* If either an old-style or new-style Diffie Helman exchange
         * has completed, the session will enter encrypted mode.
         */
        if (( (sessionp->state_flags &
            SSH_FLG_V2_DHOLD_DONE) == SSH_FLG_V2_DHOLD_DONE )
            || ( (sessionp->state_flags &
            SSH_FLG_V2_DHNEW_DONE) == SSH_FLG_V2_DHNEW_DONE ))
        {
            sessionp->state_flags |= SSH_FLG_SESS_ENCRYPTED;
            if (ssh_length < dsize)
            {
                if ( ssh_length >= 4 )
                {
                    npacket_offset += ssh_length;
                    dsize -= ssh_length;
                    continue;
                }
                return ( npacket_offset + offset );
            }
            else
                return 0;
        }

        if ((ssh_length < dsize) && (ssh_length >= 4))
        {
            npacket_offset += ssh_length;
            dsize -= ssh_length;
>>>>>>> offload
        }
        else
        {
            DetectionEngine::queue_event(GID_SSH, SSH_EVENT_WRONGDIR);
            return false;
        }
        break;
    case SSH_MSG_V1_CMSG_SESSION_KEY:
        if (direction == SSH_DIR_FROM_CLIENT)
        {
            sessionp->state_flags |= SSH_FLG_CLIENT_SKEY_SEEN;
        }
        else
        {
            DetectionEngine::queue_event(GID_SSH, SSH_EVENT_WRONGDIR);
            return false;
        }
        break;
    }
    if ((sessionp->state_flags & SSH_FLG_V1_KEYEXCH_DONE) == SSH_FLG_V1_KEYEXCH_DONE)
    {
        sessionp->state_flags |= SSH_FLG_SESS_ENCRYPTED;
    }
    return true;
}

static bool process_ssh2_kexinit(SSHData *sessionp, Packet *p, uint8_t direction)
{
    uint16_t dsize = p->dsize;
    unsigned int ssh_length = 0;
    if (dsize < sizeof(SSH2KeyExchange) or dsize > SSH_PACKET_MAX_SIZE)
    {
        DetectionEngine::queue_event(GID_SSH, SSH_EVENT_PAYLOAD_SIZE);
        return false;
    }
    const SSH2KeyExchange* ssh_pkt = (const SSH2KeyExchange*)p->data;
    ssh_length = ntohl(ssh_pkt->msg.len) + sizeof(uint32_t);
    if (ssh_length != dsize)
    {
        DetectionEngine::queue_event(GID_SSH, SSH_EVENT_PAYLOAD_SIZE);
        return false;
    }
    switch(ssh_pkt->msg.code)
    {
    case SSH_MSG_KEXINIT:
        sessionp->state_flags |=
            (direction == SSH_DIR_FROM_SERVER ?
            SSH_FLG_SERV_KEXINIT_SEEN :
            SSH_FLG_CLIENT_KEXINIT_SEEN);
        break;
    case SSH_MSG_IGNORE:
        return true;
    default:
        return false;
    }
    uint16_t total_length = sizeof(SSH2KeyExchange);
    const uint8_t *data = p->data + sizeof(SSH2KeyExchange);
    for (int i = 0; i < NUM_KEXINIT_LISTS; i++)
    {
        uint32_t list_length = ntohl(*((const uint32_t*)data)) + sizeof(uint32_t);
        if (list_length > ssh_length or total_length + list_length > ssh_length)
        {
            DetectionEngine::queue_event(GID_SSH, SSH_EVENT_PAYLOAD_SIZE);
            return false;
        }
        total_length += list_length;
        data += list_length;
    }
    total_length += sizeof(SSHKeyExchangeFinal) + ssh_pkt->msg.plen;
    if (total_length != ssh_length)
    {
        DetectionEngine::queue_event(GID_SSH, SSH_EVENT_PAYLOAD_SIZE);
        return false;
    }
    const SSHKeyExchangeFinal* final = (const SSHKeyExchangeFinal*)data;
    if (final->future)
    {
        // using an unsupported future version
        return false;
    }
    return true;
}

static bool process_ssh2_key_exchange(SSHData *sessionp, Packet *p, uint8_t direction)
{
    uint16_t dsize = p->dsize;
    const unsigned char *data = p->data;

    if (dsize < sizeof(SSH2Packet))
    {
        return false;
    }

    const SSH2Packet *ssh2p = (const SSH2Packet *)data;
    unsigned ssh_length = ntohl(ssh2p->packet_length) + sizeof(uint32_t);

    if (ssh_length < sizeof(SSH2Packet)
        or ssh_length != dsize
        or ssh_length > SSH_PACKET_MAX_SIZE)
    {
        /* Invalid packet length. */
        DetectionEngine::queue_event(GID_SSH, SSH_EVENT_PAYLOAD_SIZE);
        return false;
    }

    switch (ssh2p->packet_data)
    {
    case SSH_MSG_KEXDH_INIT:
        if (direction == SSH_DIR_FROM_CLIENT)
        {
            sessionp->state_flags |=
                SSH_FLG_KEXDH_INIT_SEEN;
        }
        else
        {
            /* Client msg from server. */
            DetectionEngine::queue_event(GID_SSH, SSH_EVENT_WRONGDIR);
        }
        break;
    case SSH_MSG_KEXDH_REPLY:
        if (direction == SSH_DIR_FROM_SERVER)
        {
            /* KEXDH_REPLY has the same msg
             * type as the new style GEX_REPLY
             */
            sessionp->state_flags |=
                SSH_FLG_KEXDH_REPLY_SEEN |
                SSH_FLG_GEX_REPLY_SEEN;
        }
        else
        {
            /* Server msg from client. */
            DetectionEngine::queue_event(GID_SSH, SSH_EVENT_WRONGDIR);
        }
        break;
    case SSH_MSG_KEXDH_GEX_REQ:
        if (direction == SSH_DIR_FROM_CLIENT)
        {
            sessionp->state_flags |=
                SSH_FLG_GEX_REQ_SEEN;
        }
        else
        {
            /* Server msg from client. */
            DetectionEngine::queue_event(GID_SSH, SSH_EVENT_WRONGDIR);
        }
        break;
    case SSH_MSG_KEXDH_GEX_GRP:
        if (direction == SSH_DIR_FROM_SERVER)
        {
            sessionp->state_flags |=
                SSH_FLG_GEX_GRP_SEEN;
        }
        else
        {
            /* Client msg from server. */
            DetectionEngine::queue_event(GID_SSH, SSH_EVENT_WRONGDIR);
        }
        break;
    case SSH_MSG_KEXDH_GEX_INIT:
        if (direction == SSH_DIR_FROM_CLIENT)
        {
            sessionp->state_flags |=
                SSH_FLG_GEX_INIT_SEEN;
        }
        else
        {
            /* Server msg from client. */
            DetectionEngine::queue_event(GID_SSH, SSH_EVENT_WRONGDIR);
        }
        break;
    case SSH_MSG_NEWKEYS:
        /* This message is required to complete the
         * key exchange. Both server and client should
         * send one, but as per Alex Kirk's note on this,
         * in some implementations the server does not
         * actually send this message. So receiving a new
         * keys msg from the client is sufficient.
         */
        if (direction == SSH_DIR_FROM_CLIENT)
        {
            sessionp->state_flags |= SSH_FLG_CLIENT_NEWKEYS_SEEN;
        }
        else
        {
            sessionp->state_flags |= SSH_FLG_SERVER_NEWKEYS_SEEN;
        }
        break;
    default:
        return false;
    }

    /* If either an old-style or new-style Diffie Helman exchange
     * has completed, the session will enter encrypted mode.
     */
    if (((sessionp->state_flags & SSH_FLG_V2_DHOLD_DONE) == SSH_FLG_V2_DHOLD_DONE)
        or ((sessionp->state_flags & SSH_FLG_V2_DHNEW_DONE) == SSH_FLG_V2_DHNEW_DONE))
    {
        sessionp->state_flags |= SSH_FLG_SESS_ENCRYPTED;
    }
    return true;
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Ssh : public Inspector
{
public:
    Ssh(SSH_PROTO_CONF*);
    ~Ssh() override;

    bool configure(SnortConfig*) override;
    void show(const SnortConfig*) const override;
    void eval(Packet*) override;
    class StreamSplitter* get_splitter(bool to_server) override
    { return new SshSplitter(to_server); }

private:
    SSH_PROTO_CONF* config;
};

Ssh::Ssh(SSH_PROTO_CONF* pc)
{
    config = pc;
}

Ssh::~Ssh()
{
    if ( config )
        delete config;
}

bool Ssh::configure(SnortConfig*)
{
    pub_id = DataBus::get_id(ssh_pub_key);
    return true;
}

void Ssh::show(const SnortConfig*) const
{
    if ( !config )
        return;

    ConfigLogger::log_value("max_encrypted_packets", config->MaxEncryptedPackets);
    ConfigLogger::log_value("max_client_bytes", config->MaxClientBytes);
    ConfigLogger::log_value("max_server_version_len", config->MaxServerVersionLen);
}

void Ssh::eval(Packet* p)
{
    // precondition - what we registered for
    assert(p->has_tcp_data());
    assert(p->flow);

    ++sshstats.total_packets;
    snort_ssh(config, p);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new SshModule; }

static void mod_dtor(Module* m)
{ delete m; }

static void ssh_init()
{
    SshFlowData::init();
}

static Inspector* ssh_ctor(Module* m)
{
    SshModule* mod = (SshModule*)m;
    return new Ssh(mod->get_data());
}

static void ssh_dtor(Inspector* p)
{
    delete p;
}

const InspectApi ssh_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        SSH_NAME,
        SSH_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__PDU,
    nullptr, // buffers
    "ssh",
    ssh_init,
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ssh_ctor,
    ssh_dtor,
    nullptr, // ssn
    nullptr  // reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &ssh_api.base,
    nullptr
};
#else
const BaseApi* sin_ssh = &ssh_api.base;
#endif

