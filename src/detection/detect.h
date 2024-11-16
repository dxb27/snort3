//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

#ifndef DETECT_H
#define DETECT_H

#include "main/snort_types.h"

namespace snort
{
struct Packet;
struct ProfileStats;
}

<<<<<<< HEAD
struct ListHead;
struct OptTreeNode;

extern THREAD_LOCAL snort::ProfileStats eventqPerfStats;

// main loop hooks
bool snort_ignore(snort::Packet*);
bool snort_log(snort::Packet*);
=======
extern THREAD_LOCAL ProfileStats eventqPerfStats;
extern THREAD_LOCAL ProfileStats detectPerfStats;
extern THREAD_LOCAL ProfileStats rebuiltPacketPerfStats;

// main loop hooks
void snort_ignore(Packet*);
void snort_log(Packet*);
>>>>>>> offload

// alerts
void CallLogFuncs(snort::Packet*, ListHead*, class Event*, const char*);
void CallLogFuncs(snort::Packet*, const OptTreeNode*, ListHead*);
void CallAlertFuncs(snort::Packet*, const OptTreeNode*, ListHead*);

void enable_tags();
<<<<<<< HEAD
void check_tags(snort::Packet*);
=======
void check_tags(Packet*);
>>>>>>> offload

#endif

