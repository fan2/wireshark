do
    --[[
    Proto.new(name, desc)
        name: displayed in the column of ¡°Protocol¡± in the packet list
        desc: displayed as the dissection tree root in the packet details
    --]]
    local PROTO_ROH = Proto("ROH", "Rtp Over Http")
    local PROTO_PANASONIC_PTZ = Proto("PANASONIC_PTZ", "Panasonic PTZ Protocol")

    --[[
    ProtoField:
        to be used when adding items to the dissection tree
    --]]
    --[[
    1.ROH ProtoField
    --]]
    --rtp over http header flag(1 byte)
    local f_roh_headerflag = ProtoField.uint8("ROH.HeaderFlag", "Header Flag", base.HEX)
    --rtp over http interleaved channel(1 byte)
    local f_roh_interleave = ProtoField.uint8("ROH.InterleavedChannel", "Interleaved Channel", base.DEC)
    --rtp over http packet length(2 bytes)
    local f_roh_packlen = ProtoField.uint16("ROH.PacketLen", "Packet Length", base.DEC)
    --define the fields table of this dissector(as a protoField array)
    PROTO_ROH.fields = {f_roh_headerflag, f_roh_interleave, f_roh_packlen}
    
    --[[
    2.PANASONIC_PTZ ProtoField
    --]]
    -- panasonic ptz header flag(32 ascii)
    local f_panasonic_ptz_flag = ProtoField.bytes("PANASONIC_PTZ", "Header Flag")
    -- panasonic ptz command(6~17 ascii)
    local f_panasonic_ptz_cmd = ProtoField.bytes("PANASONIC_PTZ", "Command")
    --define the fields table of this dissector(as a protoField array)
    PROTO_PANASONIC_PTZ.fields = {f_panasonic_ptz_flag, f_panasonic_ptz_cmd}

    --[[
    Data Section
    --]]
    local data_dis = Dissector.get("data")

    --[[
    ROH Dissector Function
    --]]
    local function roh_dissector(buf, pkt, root)

        -- check buffer length
        local buf_len = buf:len()
        if buf_len < 16
        then
            return false
        end
        
        -- check header flag
        if buf(0,2):uint() ~= 0x2400
        then
            return false
        end

        --[[
        packet list columns
        --]]
        pkt.cols.protocol = "ROH"
        pkt.cols.info = "Rtp Over Http"

        --[[
        dissection tree in packet details
        --]]
        -- tree root
        local t = root:add(PROTO_ROH, buf(0,4))
        -- child items
        t:add(f_roh_headerflag, buf(0,1))
        t:add(f_roh_interleave, buf(1,1))
        t:add(f_roh_packlen, buf(2,2))

        return true
    end

    --[[
    PANASONIC_PTZ Dissector Function Helper
    --]]
    local function get_cmd_len(buf)
        local found=nil
        for i=0,17 do
            if buf(i,1):uint() == 0x26
            then
                found = i
                break
            end
        end
        return found
    end
        
    --[[
    PANASONIC_PTZ Dissector Function
    --]]
    local function panasonic_ptz_dissector(buf, pkt, root)

        -- check buffer length
        local buf_len = buf:len()
        if buf_len < 32
        then
            return false
        end
        
        -- check header flag
        if buf(0,32):string() ~= "GET /nphControlCamera?Direction="
        then
            return false
        end
        
        -- check direction
        local sub_buf = buf(32, 18):tvb()
        local cmd_len = get_cmd_len(sub_buf)
                        
        if cmd_len > 0
        then
            --[[
            packet list columns
            --]]
            pkt.cols.protocol = "PANASONIC_PTZ"
            pkt.cols.info = "Panasonic PTZ Protocol"
            
            --[[
            dissection tree in packet details
            --]]
            -- tree root
            local t = root:add(PROTO_PANASONIC_PTZ, buf(0,buf_len))
            -- child items
            local flag = t:add(f_panasonic_ptz_flag, buf(0,32))
            flag:add(buf(0,31), "["..buf(0,31):string().."]")
            local cmd = t:add(f_panasonic_ptz_cmd, buf(32,cmd_len))
            cmd:add(buf(32,cmd_len), "["..buf(32,cmd_len):string().."]")
        else
            return false
        end

        return true
    end

    --[[
    Dissect Process
    --]]
    function PROTO_ROH.dissector(buf, pkt, root)
        if roh_dissector(buf, pkt, root)
        then
            -- skip over rtp over http header
            local rtp_buf = buf(4,buf:len()-4):tvb()
            -- call internal rtp dissector
            local rtp_dissector = Dissector.get("rtp")
            rtp_dissector:call(rtp_buf, pkt, root)
        elseif panasonic_ptz_dissector(buf, pkt, root)
        then
            -- valid ptz datagram
        else
            data_dis:call(buf, pkt, root)
        end
    end

    --[[
    Specify Protocol Port
    --]]
    local tcp_encap_table = DissectorTable.get("tcp.port")
    tcp_encap_table:add(80, PROTO_ROH)
end