//--------------------------------------------------------------------------
<<<<<<< HEAD
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
=======
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
>>>>>>> offload
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

// rtn_checks.cc is part of work originally done by:
//
//     Dan Roelker <droelker@sourcefire.com>
//     Marc Norton <mnorton@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rtn_checks.h"

<<<<<<< HEAD
#include "framework/ips_option.h"
=======
#include "main/snort_debug.h"
>>>>>>> offload
#include "ports/port_object.h"
#include "protocols/packet.h"
#include "sfip/sf_ip.h"
#include "sfip/sf_ipvar.h"

<<<<<<< HEAD
#include "rules.h"
#include "treenodes.h"

using namespace snort;

=======
#include "detection_defines.h"
#include "rules.h"
#include "treenodes.h"

>>>>>>> offload
#define CHECK_SRC_IP         0x01
#define CHECK_DST_IP         0x02
#define INVERSE              0x04
#define CHECK_SRC_PORT       0x08
#define CHECK_DST_PORT       0x10

<<<<<<< HEAD
static int CheckAddrPort(sfip_var_t* rule_addr, PortObject* po, Packet* p,
    uint32_t flags, int mode)
{
    const SfIp* pkt_addr;
    unsigned short pkt_port;
    int any_port_flag = 0;
    int ip_match = 0;

=======
static int CheckAddrPort(
    sfip_var_t* rule_addr,
    PortObject* po,
    Packet* p,
    uint32_t flags, int mode)
{
    const SfIp* pkt_addr;          /* packet IP address */
    u_short pkt_port;                /* packet port */
    int global_except_addr_flag = 0; /* global exception flag is set */
    int any_port_flag = 0;           /* any port flag set */
    int except_port_flag = 0;        /* port exception flag set */
    int ip_match = 0;                /* flag to indicate addr match made */

    DebugMessage(DEBUG_DETECT, "CheckAddrPort: ");
>>>>>>> offload
    /* set up the packet particulars */
    if (mode & CHECK_SRC_IP)
    {
        pkt_addr = p->ptrs.ip_api.get_src();
        pkt_port = p->ptrs.sp;

<<<<<<< HEAD
        if (mode & INVERSE)
            any_port_flag = flags & RuleTreeNode::ANY_DST_PORT;
        else
            any_port_flag = flags & RuleTreeNode::ANY_SRC_PORT;
=======
        DebugMessage(DEBUG_DETECT,"SRC ");

        if (mode & INVERSE)
        {
            global_except_addr_flag = flags & EXCEPT_DST_IP;
            any_port_flag = flags & ANY_DST_PORT;
            except_port_flag = flags & EXCEPT_DST_PORT;
        }
        else
        {
            global_except_addr_flag = flags & EXCEPT_SRC_IP;
            any_port_flag = flags & ANY_SRC_PORT;
            except_port_flag = flags & EXCEPT_SRC_PORT;
        }
>>>>>>> offload
    }
    else
    {
        pkt_addr = p->ptrs.ip_api.get_dst();
        pkt_port = p->ptrs.dp;

<<<<<<< HEAD
        if (mode & INVERSE)
            any_port_flag = flags & RuleTreeNode::ANY_SRC_PORT;
        else
            any_port_flag = flags & RuleTreeNode::ANY_DST_PORT;
    }

    if (!rule_addr)
        goto bail;

    if (sfvar_ip_in(rule_addr, pkt_addr))
        ip_match = 1;

bail:
    if (!ip_match)
        return 0;

    /* if the any port flag is up, we're all done (success) */
    if (any_port_flag)
        return 1;

    if (!(mode & (CHECK_SRC_PORT | CHECK_DST_PORT)))
        return 1;

    /* check the packet port against the rule port */
    /* if the exception flag isn't up, fail */
    if ( !PortObjectHasPort(po, pkt_port) )
        return 0;

    /* ports and address match */
=======
        DebugMessage(DEBUG_DETECT, "DST ");

        if (mode & INVERSE)
        {
            global_except_addr_flag = flags & EXCEPT_SRC_IP;
            any_port_flag = flags & ANY_SRC_PORT;
            except_port_flag = flags & EXCEPT_SRC_PORT;
        }
        else
        {
            global_except_addr_flag = flags & EXCEPT_DST_IP;
            any_port_flag = flags & ANY_DST_PORT;
            except_port_flag = flags & EXCEPT_DST_PORT;
        }
    }

    DebugFormat(DEBUG_DETECT, "addr %s, port %d ", pkt_addr->ntoa(), pkt_port);

    if (!rule_addr)
        goto bail;

    if (!(global_except_addr_flag)) /*modeled after Check{Src,Dst}IP function*/
    {
        if (sfvar_ip_in(rule_addr, pkt_addr))
            ip_match = 1;
    }
    else
    {
        DebugMessage(DEBUG_DETECT, ", global exception flag set");
        /* global exception flag is up, we can't match on *any*
         * of the source addresses
         */

        if (sfvar_ip_in(rule_addr, pkt_addr))
            return 0;

        ip_match=1;
    }

bail:
    if (!ip_match)
    {
        DebugMessage(DEBUG_DETECT, ", no address match,  "
            "packet rejected\n");
        return 0;
    }

    DebugMessage(DEBUG_DETECT, ", addresses accepted");

    /* if the any port flag is up, we're all done (success) */
    if (any_port_flag)
    {
        DebugMessage(DEBUG_DETECT, ", any port match, "
            "packet accepted\n");
        return 1;
    }

    if (!(mode & (CHECK_SRC_PORT | CHECK_DST_PORT)))
    {
        return 1;
    }

    /* check the packet port against the rule port */
    if ( !PortObjectHasPort(po,pkt_port) )
    {
        /* if the exception flag isn't up, fail */
        if (!except_port_flag)
        {
            DebugMessage(DEBUG_DETECT, ", port mismatch,  "
                "packet rejected\n");
            return 0;
        }
        DebugMessage(DEBUG_DETECT, ", port mismatch exception");
    }
    else
    {
        /* if the exception flag is up, fail */
        if (except_port_flag)
        {
            DebugMessage(DEBUG_DETECT,
                ", port match exception,  packet rejected\n");
            return 0;
        }
        DebugMessage(DEBUG_DETECT, ", ports match");
    }

    /* ports and address match */
    DebugMessage(DEBUG_DETECT, ", packet accepted!\n");
>>>>>>> offload
    return 1;
}

#define CHECK_ADDR_SRC_ARGS(x) (x)->src_portobject
#define CHECK_ADDR_DST_ARGS(x) (x)->dst_portobject

int CheckBidirectional(Packet* p, RuleTreeNode* rtn_idx,
    RuleFpList*, int check_ports)
{
<<<<<<< HEAD
    if (CheckAddrPort(rtn_idx->sip, CHECK_ADDR_SRC_ARGS(rtn_idx), p,
        rtn_idx->flags, CHECK_SRC_IP | (check_ports ? CHECK_SRC_PORT : 0)))
    {
        if (!CheckAddrPort(rtn_idx->dip, CHECK_ADDR_DST_ARGS(rtn_idx), p,
            rtn_idx->flags, CHECK_DST_IP | (check_ports ? CHECK_DST_PORT : 0)))
        {
            if (CheckAddrPort(rtn_idx->dip, CHECK_ADDR_DST_ARGS(rtn_idx), p,
                rtn_idx->flags, (CHECK_SRC_IP | INVERSE | (check_ports ? CHECK_SRC_PORT : 0))))
            {
                if (!CheckAddrPort(rtn_idx->sip, CHECK_ADDR_SRC_ARGS(rtn_idx), p, rtn_idx->flags,
                    (CHECK_DST_IP | INVERSE | (check_ports ? CHECK_DST_PORT : 0))))
                {
                    return 0;
                }
            }
            else
            {
                return 0;
            }
        }
    }
    else
    {
        if (CheckAddrPort(rtn_idx->dip, CHECK_ADDR_DST_ARGS(rtn_idx), p,
            rtn_idx->flags, CHECK_SRC_IP | INVERSE | (check_ports ? CHECK_SRC_PORT : 0)))
        {
            if (!CheckAddrPort(rtn_idx->sip, CHECK_ADDR_SRC_ARGS(rtn_idx), p,
                rtn_idx->flags, CHECK_DST_IP | INVERSE | (check_ports ? CHECK_DST_PORT : 0)))
            {
=======
    DebugMessage(DEBUG_DETECT, "Checking bidirectional rule...\n");

    if (CheckAddrPort(rtn_idx->sip, CHECK_ADDR_SRC_ARGS(rtn_idx), p,
        rtn_idx->flags, CHECK_SRC_IP | (check_ports ? CHECK_SRC_PORT : 0)))
    {
        DebugMessage(DEBUG_DETECT, "   Src->Src check passed\n");
        if (!CheckAddrPort(rtn_idx->dip, CHECK_ADDR_DST_ARGS(rtn_idx), p,
            rtn_idx->flags, CHECK_DST_IP | (check_ports ? CHECK_DST_PORT : 0)))
        {
            DebugMessage(DEBUG_DETECT,
                "   Dst->Dst check failed, checking inverse combination\n");
            if (CheckAddrPort(rtn_idx->dip, CHECK_ADDR_DST_ARGS(rtn_idx), p,
                rtn_idx->flags, (CHECK_SRC_IP | INVERSE | (check_ports ? CHECK_SRC_PORT : 0))))
            {
                DebugMessage(DEBUG_DETECT,
                    "   Inverse Dst->Src check passed\n");
                if (!CheckAddrPort(rtn_idx->sip, CHECK_ADDR_SRC_ARGS(rtn_idx), p,
                    rtn_idx->flags, (CHECK_DST_IP | INVERSE | (check_ports ? CHECK_DST_PORT : 0))))
                {
                    DebugMessage(DEBUG_DETECT,
                        "   Inverse Src->Dst check failed\n");
                    return 0;
                }
                else
                {
                    DebugMessage(DEBUG_DETECT, "Inverse addr/port match\n");
                }
            }
            else
            {
                DebugMessage(DEBUG_DETECT, "   Inverse Dst->Src check failed,"
                    " trying next rule\n");
>>>>>>> offload
                return 0;
            }
        }
        else
        {
<<<<<<< HEAD
=======
            DebugMessage(DEBUG_DETECT, "dest IP/port match\n");
        }
    }
    else
    {
        DebugMessage(DEBUG_DETECT,
            "   Src->Src check failed, trying inverse test\n");
        if (CheckAddrPort(rtn_idx->dip, CHECK_ADDR_DST_ARGS(rtn_idx), p,
            rtn_idx->flags, CHECK_SRC_IP | INVERSE | (check_ports ? CHECK_SRC_PORT : 0)))
        {
            DebugMessage(DEBUG_DETECT,
                "   Dst->Src check passed\n");

            if (!CheckAddrPort(rtn_idx->sip, CHECK_ADDR_SRC_ARGS(rtn_idx), p,
                rtn_idx->flags, CHECK_DST_IP | INVERSE | (check_ports ? CHECK_DST_PORT : 0)))
            {
                DebugMessage(DEBUG_DETECT,
                    "   Src->Dst check failed\n");
                return 0;
            }
            else
            {
                DebugMessage(DEBUG_DETECT,
                    "Inverse addr/port match\n");
            }
        }
        else
        {
            DebugMessage(DEBUG_DETECT,"   Inverse test failed, "
                "testing next rule...\n");
>>>>>>> offload
            return 0;
        }
    }

<<<<<<< HEAD
    return 1;
}

// Purpose: Test the source IP and see if it equals the SIP of the packet
// Returns: 0 on failure (no match), 1 on success (match)
int CheckSrcIP(Packet* p, RuleTreeNode* rtn_idx, RuleFpList* fp_list, int check_ports)
{
    if ( sfvar_ip_in(rtn_idx->sip, p->ptrs.ip_api.get_src()) )
    {
        /* the packet matches this test, proceed to the next test */
        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next, check_ports);
    }

=======
    DebugMessage(DEBUG_DETECT,"   Bidirectional success!\n");
    return 1;
}

/****************************************************************************
 *
 * Function: CheckSrcIp(Packet *, RuleTreeNode *, RuleFpList *)
 *
 * Purpose: Test the source IP and see if it equals the SIP of the packet
 *
 * Arguments: p => ptr to the decoded packet data structure
 *            rtn_idx => ptr to the current rule data struct
 *            fp_list => ptr to the current function pointer node
 *
 * Returns: 0 on failure (no match), 1 on success (match)
 *
 ***************************************************************************/
int CheckSrcIP(Packet* p, RuleTreeNode* rtn_idx, RuleFpList* fp_list, int check_ports)
{
    DebugMessage(DEBUG_DETECT,"CheckSrcIPEqual: ");

    if (!(rtn_idx->flags & EXCEPT_SRC_IP))
    {
        if ( sfvar_ip_in(rtn_idx->sip, p->ptrs.ip_api.get_src()) )
        {
            /* the packet matches this test, proceed to the next test */
            return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next, check_ports);
        }
    }
    else
    {
        /* global exception flag is up, we can't match on *any*
         * of the source addresses
         */
        DebugMessage(DEBUG_DETECT,"  global exception flag, \n");

        if ( sfvar_ip_in(rtn_idx->sip, p->ptrs.ip_api.get_src()) )
            return 0;

        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next, check_ports);
    }

    DebugMessage(DEBUG_DETECT,"  Mismatch on SIP\n");

>>>>>>> offload
    /* return 0 on a failed test */
    return 0;
}

<<<<<<< HEAD
// Purpose: Test the dest IP and see if it equals the DIP of the packet
// Returns: 0 on failure (no match), 1 on success (match)
int CheckDstIP(Packet* p, RuleTreeNode* rtn_idx, RuleFpList* fp_list, int check_ports)
{
    if ( sfvar_ip_in(rtn_idx->dip, p->ptrs.ip_api.get_dst()) )
    {
        /* the packet matches this test, proceed to the next test */
        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next, check_ports);
    }
=======
/****************************************************************************
 *
 * Function: CheckDstIp(Packet *, RuleTreeNode *, RuleFpList *)
 *
 * Purpose: Test the dest IP and see if it equals the DIP of the packet
 *
 * Arguments: p => ptr to the decoded packet data structure
 *            rtn_idx => ptr to the current rule data struct
 *            fp_list => ptr to the current function pointer node
 *
 * Returns: 0 on failure (no match), 1 on success (match)
 *
 ***************************************************************************/
int CheckDstIP(Packet* p, RuleTreeNode* rtn_idx, RuleFpList* fp_list, int check_ports)
{
    DebugMessage(DEBUG_DETECT, "CheckDstIPEqual: ");

    if (!(rtn_idx->flags & EXCEPT_DST_IP))
    {
        if ( sfvar_ip_in(rtn_idx->dip, p->ptrs.ip_api.get_dst()) )
        {
            /* the packet matches this test, proceed to the next test */
            return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next, check_ports);
        }
    }
    else
    {
        /* global exception flag is up, we can't match on *any*
         * of the source addresses */
        DebugMessage(DEBUG_DETECT,"  global exception flag, \n");

        if ( sfvar_ip_in(rtn_idx->dip, p->ptrs.ip_api.get_dst()) )
            return 0;

        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next, check_ports);
    }

>>>>>>> offload
    return 0;
}

int CheckSrcPortEqual(Packet* p, RuleTreeNode* rtn_idx,
    RuleFpList* fp_list, int check_ports)
{
<<<<<<< HEAD
=======
    DebugMessage(DEBUG_DETECT,"CheckSrcPortEqual: ");

>>>>>>> offload
    /* Check if attributes provided match earlier */
    if (check_ports == 0)
    {
        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next, check_ports);
    }
    if ( PortObjectHasPort(rtn_idx->src_portobject,p->ptrs.sp) )
    {
<<<<<<< HEAD
        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next, check_ports);
    }
=======
        DebugMessage(DEBUG_DETECT, "  SP match!\n");
        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next, check_ports);
    }
    else
    {
        DebugMessage(DEBUG_DETECT, "   SP mismatch!\n");
    }

>>>>>>> offload
    return 0;
}

int CheckSrcPortNotEq(Packet* p, RuleTreeNode* rtn_idx,
    RuleFpList* fp_list, int check_ports)
{
<<<<<<< HEAD
=======
    DebugMessage(DEBUG_DETECT,"CheckSrcPortNotEq: ");

>>>>>>> offload
    /* Check if attributes provided match earlier */
    if (check_ports == 0)
    {
        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next, check_ports);
    }
    if ( !PortObjectHasPort(rtn_idx->src_portobject,p->ptrs.sp) )
    {
<<<<<<< HEAD
        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next, check_ports);
    }
=======
        DebugMessage(DEBUG_DETECT, "  !SP match!\n");
        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next, check_ports);
    }
    else
    {
        DebugMessage(DEBUG_DETECT, "  !SP mismatch!\n");
    }
>>>>>>> offload

    return 0;
}

int CheckDstPortEqual(Packet* p, RuleTreeNode* rtn_idx,
    RuleFpList* fp_list, int check_ports)
{
<<<<<<< HEAD
=======
    DebugMessage(DEBUG_DETECT,"CheckDstPortEqual: ");

>>>>>>> offload
    /* Check if attributes provided match earlier */
    if (check_ports == 0)
    {
        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next, check_ports);
    }
    if ( PortObjectHasPort(rtn_idx->dst_portobject,p->ptrs.dp) )
    {
<<<<<<< HEAD
        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next, check_ports);
    }
=======
        DebugMessage(DEBUG_DETECT, " DP match!\n");
        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next, check_ports);
    }
    else
    {
        DebugMessage(DEBUG_DETECT," DP mismatch!\n");
    }
>>>>>>> offload
    return 0;
}

int CheckDstPortNotEq(Packet* p, RuleTreeNode* rtn_idx,
    RuleFpList* fp_list, int check_ports)
{
<<<<<<< HEAD
=======
    DebugMessage(DEBUG_DETECT,"CheckDstPortNotEq: ");

>>>>>>> offload
    /* Check if attributes provided match earlier */
    if (check_ports == 0)
    {
        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next, check_ports);
    }
    if ( !PortObjectHasPort(rtn_idx->dst_portobject,p->ptrs.dp) )
    {
<<<<<<< HEAD
        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next, check_ports);
    }
=======
        DebugMessage(DEBUG_DETECT, " !DP match!\n");
        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next, check_ports);
    }
    else
    {
        DebugMessage(DEBUG_DETECT," !DP mismatch!\n");
    }
>>>>>>> offload

    return 0;
}

<<<<<<< HEAD
int CheckProto(Packet* p, RuleTreeNode* rtn_idx, RuleFpList*, int check_ports)
{
    if ( !check_ports )
        return 1;  // ignore proto when ignoring ports

    assert(rtn_idx->snort_protocol_id < SNORT_PROTO_MAX);

    const int proto_bits[SNORT_PROTO_MAX] =  // SNORT_PROTO_ to PROTO_BIT__*
    {
        /* n/a */  PROTO_BIT__NONE,
        /* ip */   PROTO_BIT__IP | PROTO_BIT__TCP | PROTO_BIT__UDP,  // legacy
        /* icmp */ PROTO_BIT__ICMP,
        /* tcp */  PROTO_BIT__TCP | PROTO_BIT__PDU,
        /* udp */  PROTO_BIT__UDP,
        /* file */ PROTO_BIT__FILE | PROTO_BIT__PDU
    };
    return proto_bits[rtn_idx->snort_protocol_id] & p->proto_bits;
}

=======
>>>>>>> offload
int RuleListEnd(Packet*, RuleTreeNode*, RuleFpList*, int)
{
    return 1;
}

<<<<<<< HEAD
=======
int OptListEnd(void*, Cursor&, Packet*)
{
    return DETECTION_OPTION_MATCH;
}

>>>>>>> offload
