-- eCapture enhances the capture data viewable in the Wireshark, will show more information about process information.
-- HomePage : https://ecapture.cc
-- Repo : https://github.com/gojue/ecapture
-- Author : CFC4N <cfc4n.cs@gmail.com>
-- License : GPL v3
-- Version : 0.1.0
-- Date : 2022-10-22

ecapture = Proto("eCapture", "eCapture enhances the capture data viewable in the Wireshark, will show more information about process information. more information: https://ecapture.cc")

local ECAPTURE_MAGIC = 0xCC0C4CFC

local fields = {}

fields.magic   = ProtoField.uint32("ecapture.magic", "Magic", base.HEX)
fields.pid     = ProtoField.int32("ecapture.pid", "PID", base.DEC)
fields.Comm = ProtoField.string("ecapture.Comm", "Comm", base.ASCII)
-- fields.Cmdline = ProtoField.string("ecapture.Cmdline", "Cmdline", base.ASCII)

ecapture.fields = fields

function ecapture.dissector(buffer, pinfo, tree)

  -- for now only IP packets are supported
  eth_header_protocol = buffer(12 ,2):uint()
  if eth_header_protocol ~= 0x800 then
    return
  end

  -- ethernet header is always 14 bytes, and after 2 bytes into IP header, you'll have IP packet's total length
  local ethernet_header_size = 14
  local iplen = buffer(16 ,2):uint()
  local framelen = buffer:len()
  local trailerlength = framelen - ethernet_header_size - iplen
  -- check padding type

  -- -4: skip the FCS
  local trailer = buffer(iplen+ethernet_header_size ,trailerlength )

  if trailerlength < 9 then
    return
  end

  -- simple sanity check with the magic number
  local magic = trailer(0, 4):uint()
  if(magic ~= ECAPTURE_MAGIC) then
--     print("trailerlength:"..trailerlength)
--     print("magic:%x", magic)
--     print("trailer:%x", trailer)
    return
  end

  local pid = trailer(4, 4):uint()

  local subtree = tree:add(ecapture, buffer(), string.format("eCapture, pid: %d",pid))
  subtree:add(fields.pid, pid)
  local commLen =  trailer(8, 1):uint()
  subtree:add(fields.Comm, trailer(9,commLen))
--   local cmdlineLen = trailer(9+commLen, 2):uint()
  -- subtree:add(fields.cmdlineLen, trailer(9+commLen,cmdlineLen))
--   local cmdline = trailer(11+commLen, cmdlineLen):string()
--   subtree:add(fields.Cmdline, cmdline)
end

register_postdissector(ecapture)