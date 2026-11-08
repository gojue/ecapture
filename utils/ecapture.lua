-- eCapture enhances the capture data viewable in the Wireshark, will show more information about process information.
-- HomePage : https://ecapture.cc
-- Repo : https://github.com/gojue/ecapture
-- Author : CFC4N <cfc4n.cs@gmail.com>
-- License : GPL v3
-- Version : 0.1.0
-- Date : 2022-10-22

ecapture = Proto("eCapture", "eCapture enhances the capture data viewable in the Wireshark, will show more information about process information. more information: https://ecapture.cc")

local ECAPTURE_MAGIC = 0xCC0C4CFC
local packet_comments = Field.new("frame.comment")

local fields = {}

fields.magic   = ProtoField.uint32("ecapture.magic", "Magic", base.HEX)
fields.pid     = ProtoField.int32("ecapture.pid", "PID", base.DEC)
fields.Comm = ProtoField.string("ecapture.Comm", "Comm", base.ASCII)
fields.Cmdline = ProtoField.string("ecapture.Cmdline", "Arguments (capture-time snapshot)")

ecapture.fields = fields

local function process_args()
  local raw, truncated
  for _, comment in ipairs({packet_comments()}) do
    local text = tostring(comment)
    if text:sub(1, 17) == "eCapture argv v1 " then
      if raw then return end
      local flag, encoded = text:match("^eCapture argv v1 ([01]) ([A-Za-z0-9+/=]+)$")
      if not flag or #encoded > 344 or #encoded % 4 ~= 0 or
          not encoded:match("^[A-Za-z0-9+/]*=?=?$") then return end
      local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
      local pad = encoded:sub(-2) == "==" and 2 or (encoded:sub(-1) == "=" and 1 or 0)
      if pad > 0 then
        local value = alphabet:find(encoded:sub(-pad-1, -pad-1), 1, true)
        if not value or (value - 1) % (pad == 2 and 16 or 4) ~= 0 then return end
      end
      raw = ByteArray.new(encoded, true):base64_decode():raw()
      truncated = flag == "1"
      if #raw == 0 or #raw > 256 or (truncated and #raw ~= 256) or
          (not truncated and raw:sub(-1) ~= "\0") then return end
    end
  end
  if not raw then return end
  local args, offset = {}, 1
  while offset <= #raw do
    local last = raw:find("\0", offset, true)
    args[#args + 1] = string.format("%q", raw:sub(offset, last and last - 1 or #raw))
    if not last then break end
    offset = last + 1
  end
  return table.concat(args, " ") .. (truncated and " [truncated at 256 bytes]" or "")
end

function ecapture.dissector(buffer, pinfo, tree)

  if buffer:len() < 14 then return end
  local eth_header_protocol = buffer(12, 2):uint()
  local header = 14
  while eth_header_protocol == 0x8100 or eth_header_protocol == 0x88a8 do
    if buffer:len() < header + 4 then return end
    eth_header_protocol = buffer(header + 2, 2):uint()
    header = header + 4
  end
  local iplen
  if eth_header_protocol == 0x800 then
    if buffer:len() < header + 20 then return end
    iplen = buffer(header + 2, 2):uint()
    if iplen < 20 then return end
  elseif eth_header_protocol == 0x86dd then
    if buffer:len() < header + 40 then return end
    iplen = 40 + buffer(header + 4, 2):uint()
  else
    return
  end
  local offset = header + iplen
  if offset > buffer:len() then return end
  -- Preserve compatibility with minimum-frame Ethernet zero padding.
  if offset < 60 and buffer:len() >= 60 then
    local padded = true
    for i = offset, 59 do
      if buffer(i, 1):uint() ~= 0 then padded = false; break end
    end
    if padded then offset = 60 end
  end
  local trailerlength = buffer:len() - offset
  if trailerlength < 9 then return end
  local trailer = buffer(offset, trailerlength)

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
  if commLen > 16 or trailerlength < 9 + commLen then return end
  subtree:add(fields.Comm, trailer(9,commLen))
  if pid ~= 0 then
    local args = process_args()
    if args then subtree:add(fields.Cmdline, args) end
  end
end

register_postdissector(ecapture)
