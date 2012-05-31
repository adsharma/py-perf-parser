#!/usr/bin/env python
#
# Copyright 2012 the V8 project authors. All rights reserved.
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#     * Neither the name of Google Inc. nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Please see http://git.kernel.org/?p=linux/kernel/git/torvalds/linux-2.6.git;a=tree;f=tools/perf
# for the gory details.

import ctypes
import sys
import optparse
import mmap
import re
import time

USAGE="""usage: %prog [OPTION]...

Analyses perf logs to produce profiles.
"""

class Descriptor(object):
  """Descriptor of a structure in the binary trace log."""

  CTYPE_MAP = {
    "u16": ctypes.c_uint16,
    "u32": ctypes.c_uint32,
    "u64": ctypes.c_uint64
  }

  def __init__(self, fields):
    class TraceItem(ctypes.Structure):
      _fields_ = Descriptor.CtypesFields(fields)

      def __str__(self):
        return ", ".join("%s: %s" % (field, self.__getattribute__(field))
                         for field, _ in TraceItem._fields_)

    self.ctype = TraceItem

  def Read(self, trace, offset):
    return self.ctype.from_buffer(trace, offset)

  @staticmethod
  def CtypesFields(fields):
    return [(field, Descriptor.CTYPE_MAP[format]) for (field, format) in fields]


TRACE_HEADER_DESC = Descriptor([
  ("magic", "u64"),
  ("size", "u64"),
  ("attr_size", "u64"),
  ("attrs_offset", "u64"),
  ("attrs_size", "u64"),
  ("data_offset", "u64"),
  ("data_size", "u64"),
  ("event_types_offset", "u64"),
  ("event_types_size", "u64")
])


PERF_EVENT_ATTR_SIZE = 80 # V3
PERF_EVENT_ATTR_DESC = Descriptor([
  ("type", "u32"),
  ("size", "u32"),
  ("config", "u64"),
  ("sample_period_or_freq", "u64"),
  ("sample_type", "u64"),
  ("read_format", "u64"),
  ("flags", "u64"),
  ("wakeup_events_or_watermark", "u32"),
  ("bt_type", "u32"),
  ("bp_addr", "u64"),
  ("bp_len", "u64"),
  ("branch_sample_type", "u64"),
])

PERF_EVENT_ID_HEADER_DESC = Descriptor([
  ("offset", "u64"),
  ("size", "u64"),
])

PERF_EVENT_ID_DESC = Descriptor([
  ("id", "u64"),
])

PERF_EVENT_HEADER_DESC = Descriptor([
  ("type", "u32"),
  ("misc", "u16"),
  ("size", "u16")
])


PERF_MMAP_EVENT_BODY_DESC = Descriptor([
  ("pid", "u32"),
  ("tid", "u32"),
  ("addr", "u64"),
  ("len", "u64"),
  ("pgoff", "u64")
])


# perf_event_attr.sample_type bits control the set of
# perf_sample_event fields.
PERF_SAMPLE_IP = 1 << 0
PERF_SAMPLE_TID = 1 << 1
PERF_SAMPLE_TIME = 1 << 2
PERF_SAMPLE_ADDR = 1 << 3
PERF_SAMPLE_READ = 1 << 4
PERF_SAMPLE_CALLCHAIN = 1 << 5
PERF_SAMPLE_ID = 1 << 6
PERF_SAMPLE_CPU = 1 << 7
PERF_SAMPLE_PERIOD = 1 << 8
PERF_SAMPLE_STREAM_ID = 1 << 9
PERF_SAMPLE_RAW = 1 << 10

# For parsing PERF_SAMPLE_READ enabled samples
PERF_FORMAT_TOTAL_TIME_ENABLED          = 1 << 0
PERF_FORMAT_TOTAL_TIME_RUNNING          = 1 << 1
PERF_FORMAT_ID                          = 1 << 2
PERF_FORMAT_GROUP                       = 1 << 3

PERF_SAMPLE_EVENT_BODY_FIELDS = [
  ("ip", "u64", PERF_SAMPLE_IP),
  ("pid", "u32", PERF_SAMPLE_TID),
  ("tid", "u32", PERF_SAMPLE_TID),
  ("time", "u64", PERF_SAMPLE_TIME),
  ("addr", "u64", PERF_SAMPLE_ADDR),
  ("id", "u64", PERF_SAMPLE_ID),
  ("stream_id", "u64", PERF_SAMPLE_STREAM_ID),
  ("cpu", "u32", PERF_SAMPLE_CPU),
  ("res", "u32", PERF_SAMPLE_CPU),
  ("period", "u64", PERF_SAMPLE_PERIOD),

  # These are filtered based on read_format
  # see PERF_SAMPLE_EVENT_READ_FORMAT_FIELDS
  ("total_time_enabled", "u64", PERF_SAMPLE_READ),
  ("total_time_running", "u64", PERF_SAMPLE_READ),
  ("primary_event", "u64", PERF_SAMPLE_READ),

  ("nr", "u64", PERF_SAMPLE_CALLCHAIN)
  # Raw data follows the callchain and is ignored.
]

PERF_SAMPLE_EVENT_READ_FORMAT_FIELDS = [
  ("total_time_enabled", "u64", PERF_FORMAT_TOTAL_TIME_ENABLED),
  ("total_time_running", "u64", PERF_FORMAT_TOTAL_TIME_RUNNING),
  ("primary_event", "u64", PERF_FORMAT_ID),
]

PERF_SAMPLE_EVENT_IP_FORMAT = "u64"


PERF_RECORD_MMAP = 1
PERF_RECORD_SAMPLE = 9


class TraceReader(object):
  """Perf (linux-2.6/tools/perf) trace file reader."""

  _TRACE_HEADER_MAGIC = 3622385352885552464 # PERFILE2

  def __init__(self, trace_name):
    self.trace_file = open(trace_name, "r")
    self.trace = mmap.mmap(self.trace_file.fileno(), 0, mmap.MAP_PRIVATE)
    self.trace_header = TRACE_HEADER_DESC.Read(self.trace, 0)
    if self.trace_header.magic != TraceReader._TRACE_HEADER_MAGIC:
      print >>sys.stderr, "Warning: unsupported trace header magic"
      print self.trace_header.magic
    self.offset = self.trace_header.data_offset
    self.limit = self.trace_header.data_offset + self.trace_header.data_size
    assert self.limit <= self.trace.size(), \
        "Trace data limit exceeds trace file size"
    self.header_size = ctypes.sizeof(PERF_EVENT_HEADER_DESC.ctype)
    assert self.trace_header.attrs_size != 0, \
        "No perf event attributes found in the trace"
    attr_size = 0
    self.attrs = []
    nattrs = self.trace_header.attrs_size/self.trace_header.attr_size
    for i in xrange(nattrs):
      attr = PERF_EVENT_ATTR_DESC.Read(self.trace,
                                       self.trace_header.attrs_offset + attr_size)
      self.attrs.append(attr)
      if attr.size == 0: attr.size = PERF_EVENT_ATTR_SIZE
      attr_size += attr.size
      id_desc = PERF_EVENT_ID_HEADER_DESC.Read(self.trace, self.trace_header.attrs_offset + attr_size)
      attr_size += ctypes.sizeof(PERF_EVENT_ID_HEADER_DESC.ctype)
      attr.ids = []
      num_ids = id_desc.size/8 # sizeof(id) == 8
      for id in xrange(num_ids):
        attr.ids.append(PERF_EVENT_ID_DESC.Read(self.trace, id_desc.offset + id * 8).id)

    self.id = {}
    for attr in self.attrs:
      for id in attr.ids:
        self.id[id] = attr

    perf_event_attr = self.attrs[0]
    self.sample_event_body_desc = self._SampleEventBodyDesc()
    self.callchain_supported = \
        (perf_event_attr.sample_type & PERF_SAMPLE_CALLCHAIN) != 0
    if self.callchain_supported:
      self.ip_struct = Descriptor.CTYPE_MAP[PERF_SAMPLE_EVENT_IP_FORMAT]
      self.ip_size = ctypes.sizeof(self.ip_struct)

  def ReadEventHeader(self):
    if self.offset >= self.limit:
      return None, 0
    offset = self.offset
    header = PERF_EVENT_HEADER_DESC.Read(self.trace, self.offset)
    self.offset += header.size
    return header, offset

  def ReadMmap(self, header, offset):
    mmap_info = PERF_MMAP_EVENT_BODY_DESC.Read(self.trace,
                                               offset + self.header_size)
    # Read null-terminated filename.
    filename = self.trace[offset + self.header_size + ctypes.sizeof(mmap_info):
                          offset + header.size]
    mmap_info.filename = filename[:filename.find(chr(0))]
    return mmap_info

  def ReadSample(self, header, offset):
    sample = self.sample_event_body_desc.Read(self.trace,
                                              offset + self.header_size)
    if not self.callchain_supported:
      return sample
    sample.ips = []
    offset += self.header_size + ctypes.sizeof(sample)
    for _ in xrange(sample.nr):
      sample.ips.append(
        self.ip_struct.from_buffer(self.trace, offset).value)
      offset += self.ip_size
    return sample

  def Dispose(self):
    self.trace.close()
    self.trace_file.close()

  def _SampleEventBodyDesc(self):
    sample_type = self.attrs[0].sample_type
    read_format = self.attrs[0].read_format
    fields = []
    read_fields = iter(PERF_SAMPLE_EVENT_READ_FORMAT_FIELDS)
    for (field, format, bit) in PERF_SAMPLE_EVENT_BODY_FIELDS:
      if (bit == PERF_SAMPLE_READ):
        rbit = read_fields.next()[-1]
        if (rbit & read_format) != 0:
          fields += [(field, format)]
	  continue
      if (bit & sample_type) != 0:
        fields += [(field, format)]
    return Descriptor(fields)

class NestedDict(dict):
    """Implementation of perl's autovivification feature."""
    def __getitem__(self, item):
        try:
            return dict.__getitem__(self, item)
        except KeyError:
            value = 0
            return value


if __name__ == "__main__":
  parser = optparse.OptionParser(USAGE)
  parser.add_option("--trace",
                    default="perf.data",
                    help="perf trace file name [default: %default]")
  parser.add_option("--quiet", "-q",
                    default=False,
                    action="store_true",
                    help="no auxiliary messages [default: %default]")
  options, args = parser.parse_args()

  if not options.quiet:
    print "Perf trace file: %s" % options.trace

  # Stats.
  events = 0
  event = NestedDict()
  ticks = 0

  # Process the snapshot log to fill the snapshot name map.
  trace_reader = TraceReader(options.trace)
  while True:
    header, offset = trace_reader.ReadEventHeader()
    if not header:
      break
    events += 1
    if header.type == PERF_RECORD_MMAP:
      mmap_info = trace_reader.ReadMmap(header, offset)
    elif header.type == PERF_RECORD_SAMPLE:
      ticks += 1
      sample = trace_reader.ReadSample(header, offset)
      attr = trace_reader.id[sample.id]
      event[attr.config] += 1
      if trace_reader.callchain_supported:
        for ip in sample.ips:
	  pass

  if not options.quiet:
    print
    print "Stats:"
    print "%10d total trace events" % events
    print "       event ids:   %s" % event
    print "%10d total ticks" % ticks

  trace_reader.Dispose()
