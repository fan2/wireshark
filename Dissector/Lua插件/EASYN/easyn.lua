do
    --[[
    Proto.new(name, desc)
        name: displayed in the column of ¡°Protocol¡± in the packet list
        desc: displayed as the dissection tree root in the packet details
    --]]
    local PROTO_EASYN_STREAM = Proto("EASYN_STREAM", "Easyn Stream Protocol")
    local PROTO_EASYN_PTZ = Proto("EASYN_PTZ", "Easyn PTZ Protocol")

    --[[
    ProtoField:
        to be used when adding items to the dissection tree
    --]]
    --[[
    1.Easyn Stream Protocol
    --]]
    -- easyn stream header flag(4 bytes)
    local f_easyn_stream_headerflag = ProtoField.uint32("EASYN_STREAM.HeaderFlag", "Header Flag", base.HEX)
    -- easyn stream padding byte(1 byte)
    local f_easyn_stream_padding1 = ProtoField.uint8("EASYN_STREAM.Padding1", "Padding1", base.DEC)
    -- easyn stream payload length(2 bytes)
    local f_easyn_stream_packlen = ProtoField.uint16("EASYN_STREAM.PacketLen", "Packet Length", base.DEC)
    -- easyn stream padding byte(1 byte)
    local f_easyn_stream_padding2 = ProtoField.uint8("EASYN_STREAM.Padding2", "Padding2", base.DEC)
    -- easyn strean frame flag(2 bytes)
    local f_easyn_stream_frametype = ProtoField.uint16("EASYN_STREAM.FrameType", "Frame Type", base.HEX)
    -- easyn stream padding bytes(6 byte)
    local f_easyn_stream_padding3 = ProtoField.bytes("EASYN_STREAM.Padding3", "Padding3")
    --define the fields table of this dissector(as a protoField array)
    PROTO_EASYN_STREAM.fields = {f_easyn_stream_headerflag, f_easyn_stream_padding1, f_easyn_stream_packlen, f_easyn_stream_padding2, f_easyn_stream_frametype, f_easyn_stream_padding3}
    
    --[[
    2.Easyn Control Protocol
    --]]
    -- easyn ptz header flag(11 ascii)
    local f_easyn_ptz_headerflag = ProtoField.bytes("EASYN_PTZ", "Header Flag")
    -- easyn ptz command(16 ascii)
    local f_easyn_ptz_cmd = ProtoField.bytes("EASYN_PTZ", "Command")
    --define the fields table of this dissector(as a protoField array)
    PROTO_EASYN_PTZ.fields = {f_easyn_ptz_headerflag, f_easyn_ptz_cmd}

    --[[
    Data Section
    --]]
    local data_dis = Dissector.get("data")

    --[[
    EASYN_STREAM Dissector Function
    --]]
    local function easyn_stream_dissector(buf, pkt, root)

        -- check buffer length
        local buf_len = buf:len()
        if buf_len < 16
        then
            return false
        end
        
        -- check header flag        
        if buf(0,4):uint() ~= 0x000001a5
        then
            return false
        end

        --[[
        packet list columns
        --]]
        pkt.cols.protocol = "EASYN_STREAM"
        pkt.cols.info = "Easyn Stream Protocol"

        --[[
        dissection tree in packet details
        --]]
        -- tree root
        local t = root:add(PROTO_EASYN_STREAM, buf(0,16))
        -- child items
        t:add(f_easyn_stream_headerflag, buf(0,4))
        t:add(f_easyn_stream_padding1, buf(4,1))
        t:add_le(f_easyn_stream_packlen, buf(5,2))
        t:add(f_easyn_stream_padding2, buf(7,1))
        
        local v_frame_type = buf(8,2):uint()
        local f = t:add(f_easyn_stream_frametype, buf(8,2))
        
        if v_frame_type==0x6540
        then
            f:add(buf(8,2), "<I Frame>")
        elseif v_frame_type==0x6580
        then
            f:add(buf(8,2), "</I Frame>")        
        elseif v_frame_type==0x6560
        then
            f:add(buf(8,2), "<P Frame>")
        elseif v_frame_type==0x65a0
        then
            f:add(buf(8,2), "</P Frame>")            
        elseif v_frame_type==0x0000
        then
            f:add(buf(8,2), "(Stream)")
        else
            f:set_text("(VOS)")
            local v_frame_dim = buf(9,1):uint()
            if v_frame_dim == 0x02
            then
                f:add(buf(9,1), "D1(720x576)")            
            elseif v_frame_dim == 0x00
            then
                f:add(buf(9,1), "CIF(352x288)")            
            elseif v_frame_dim == 0x01
            then
                f:add(buf(9,1), "Half D1(720x288)")         
            elseif v_frame_dim == 0x06
            then
                f:add(buf(9,1), "QCIF(176x144)")
            end
        end
        
        t:add(f_easyn_stream_padding3, buf(10,6))
        
        local data_len = buf:len()-16
        local d = root:add(buf(16,data_len), "Data")
        d:append_text("("..data_len.." bytes)")
        d:add(buf(16, data_len), "Data: ")
        d:add(buf(16,0), "[Length: "..data_len.."]")

        return true
    end

    --[[
    EASYN_PTZ Dissector Function
    --]]
    local function easyn_ptz_dissector(buf, pkt, root)

        -- check buffer length
        local buf_len = buf:len()
        if buf_len < 54
        then
            return false
        end
        
        -- check header flag        
        if buf(0,11):string() ~= "GET /ptzcmd"
        then
            return false
        end

        --[[
        packet list columns
        --]]
        pkt.cols.protocol = "EASYN_PTZ"
        pkt.cols.info = "Easyn PTZ Protocol"

        --[[
        dissection tree in packet details
        --]]
        -- tree root
        local t = root:add(PROTO_EASYN_PTZ, buf(0,buf_len))
        -- child items
        local flag = t:add(f_easyn_ptz_headerflag, buf(0,11))
        flag:add(buf(0,11), "["..buf(0,11):string().."]")        
        local cmd = t:add(f_easyn_ptz_cmd, buf(29,16))
        local dir = cmd:add(buf(29,16), "["..buf(29,16):string().."]")
        
        local v_cmd = buf(29,16):string()
        if v_cmd == "0xff010008003f48"
        then
            dir:append_text("(up)")
        elseif v_cmd == "0xff010010003f50"
        then
            dir:append_text("(down)")        
        elseif v_cmd == "0xff0100023f0042"
        then
            dir:append_text("(left)")
        elseif v_cmd == "0xff0100043f0044"
        then
            dir:append_text("(right)")
        elseif v_cmd == "0xff019000000091"
        then
            dir:append_text("(rotate)")
        elseif v_cmd == "0xff010000000001"
        then
            dir:append_text("(suffix)")
        end
        
        return true
    end

    --[[
    Dissect Process
    --]]
    function PROTO_EASYN_STREAM.dissector(buf, pkt, root)
        if easyn_stream_dissector(buf, pkt, root)
        then
            -- valid easyn stream datagram
        elseif easyn_ptz_dissector(buf, pkt, root)
        then
            -- valid easyn ptz datagram
        else
            data_dis:call(buf, pkt, root)
        end
    end

    --[[
    Specify Protocol Port: should disable http!
    --]]
    local tcp_encap_table = DissectorTable.get("tcp.port")
    tcp_encap_table:add(80, PROTO_EASYN_STREAM)
end