package server

import (
	"encoding/binary"
	"log"
	"net"
	"openvpnHoney/global"
	"openvpnHoney/protocol"
	"strconv"
)

func OpenVpnTcpServer() {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(global.ServerPort))
	if err != nil {
		log.Println("[OpenVPN] socket listen error:", err)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[OpenVPN] %s socket error:%s", conn.RemoteAddr().String(), err.Error())
			continue
		} else {
			log.Printf("[OpenVPN] %s socket create", conn.RemoteAddr().String())
		}

		// generate client
		client := global.ClientMapInstance.GetClient(conn.RemoteAddr().String())
		if client == nil {
			// tlsConn
			tlsConn := TLSClient(conn.RemoteAddr().String())
			if tlsConn == nil {
				continue
			}
			// client
			client = &global.Client{
				Ch:      make(chan []byte, 100),
				CliAddr: conn.RemoteAddr().String(),
				TLSAddr: tlsConn.LocalAddr().String(),
				CliConn: conn,
				TLSConn: tlsConn,
				State:   global.S_INITIAL,
			}
			global.ClientMapInstance.SetClient(client.TLSAddr, client)
		}

		go TcpStateProcess(client)
	}
}

func TcpStateProcess(client *global.Client) {
	defer func() {
		log.Printf("[OpenVPN] %s socket close", client.CliAddr)
		if r := recover(); r != nil {
			log.Println("StateProcess:", r)
		}
		global.ClientMapInstance.DestroyClient(client.TLSAddr)
	}()

	// pre start
	client.State = global.S_PRE_START

	for {
		buffer := make([]byte, 2048)

		var reqTLSPayload []byte
		var respTLSPayload []byte

		// read base packet -> length&type[opcode、keyid]
		num, err := client.CliConn.Read(buffer[:2+1])
		if err != nil || num != 2+1 {
			//log.Println("[OpenVPN] P_CONTROL_HARD_RESET_CLIENT read total length error:", err, buffer[:num])
			return
		}

		// extract base packet
		reqBP := protocol.BasePacket{}
		reqBP.TcpUnMarshal(buffer)

		// opcode & key id
		opcode := protocol.GetOpcodeByType(reqBP.Type)
		keyId := protocol.GetKeyIDByType(reqBP.Type)

		// check opcode
		if opcode > protocol.P_LAST_OPCODE || opcode <= 0 {
			//log.Println("Error Opcode :" + strconv.Itoa(int(opcode)))
			return
		}

		// read base packet->payload
		num, err = client.CliConn.Read(buffer[:reqBP.Length-1])
		if err != nil || uint16(num) != reqBP.Length-1 {
			//log.Println("[OpenVPN] P_CONTROL_HARD_RESET_CLIENT read packet length error:", err, buffer[:num])
			return
		}
		// extract control packet
		{
			cp := protocol.ControlPacket{}
			reqBP.Payload = &cp
			cp.UnMarshal(buffer[:num], opcode)
			// set sid
			if cp.SessionID > 0 {
				client.RemoteSessionID = cp.SessionID
			}
			// set tls payload
			reqTLSPayload = cp.TLSPayload
		}

		// set state
		if client.State < global.S_START {
			client.State = global.S_START
		}

		// set RecvPacketID
		if protocol.IsValidPacket(opcode) {
			client.RecvPacketIDCount += 1
		}

		// set local session id
		if client.LocalSessionID == 0 {
			client.LocalSessionID = binary.BigEndian.Uint64(protocol.RandBytes(8))
		}

		// skip resp P_ACK_V1
		if opcode == protocol.P_ACK_V1 {
			continue
		}

		// decrypt data
		if len(reqTLSPayload) > 0 {
			// tls req packet
			if client.State < global.S_SENT_KEY {
				log.Printf("[OpenVPN] %s tls handshake", client.CliAddr)
			}
			client.TLSConn.Write(reqTLSPayload)

			// tls resp packet
			tlsPayloadLength, err := client.TLSConn.Read(buffer)
			if err != nil {
				return
			}

			// tls resp overlay openvpn
			respTLSPayload = buffer[:tlsPayloadLength]
			//log.Println("[OpenVPN] tls resp packet:", tlsPayloadLength, respTLSPayload)
		}

		// generate control packet
		{
			// marshal control packet
			respCP := protocol.ControlPacket{
				SessionID:                  client.LocalSessionID,
				MessagePacketIDArrayLength: client.RecvPacketIDCount,
				MessagePacketID:            client.SendPacketIDCount,
				RemoteSessionID:            client.RemoteSessionID,
				TLSPayload:                 respTLSPayload,
			}

			// generate resp MessagePacketIDArrayElement
			if respCP.MessagePacketIDArrayLength > 0 {
				respCP.MessagePacketIDArrayElement = make([]uint32, respCP.MessagePacketIDArrayLength)
				for i := uint8(0); i < respCP.MessagePacketIDArrayLength; i++ {
					respCP.MessagePacketIDArrayElement[i] = uint32(respCP.MessagePacketIDArrayLength - i - 1)
				}
			}
			payload := respCP.Marshal()

			// marshal base packet
			respBP := protocol.BasePacket{
				Length: uint16(1 + len(payload)),
				Type:   protocol.GetRespType(opcode, keyId),
			}
			resp := respBP.TcpMarshal(payload)
			client.CliConn.(*net.TCPConn).Write(resp)
		}

		client.SendPacketIDCount += 1
	}
}
