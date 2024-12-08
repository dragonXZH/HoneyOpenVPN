package server

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"openvpnHoney/global"
	"openvpnHoney/protocol"
	"strconv"
	"time"
)

func OpenVpnUdpServer() {
	// parse addr
	addr, err := net.ResolveUDPAddr("udp", ":"+strconv.Itoa(global.ServerPort))
	if err != nil {
		fmt.Println("Error resolving address:", err)
		return
	}

	// listen connect
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Println("Error listening:", err)
		return
	} else {
		fmt.Println("UDP server is listening on port", conn.LocalAddr().String())
	}

	// loop
	buffer := make([]byte, 2048)
	for {
		readNum, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("Error reading from UDP connection:", err)
			continue
		}

		if readNum < 3 {
			fmt.Println("Error reading from UDP connection length:", readNum)
			continue
		}

		// tlsConn
		tlsConn := TLSClient()
		if tlsConn == nil {
			continue
		}

		// client
		client := global.ClientMapInstance.GetClient(clientAddr.String())
		if client == nil {
			client = global.InitClient(conn, tlsConn, global.S_INITIAL)
			global.ClientMapInstance.SetClient(clientAddr.String(), client)
			global.ClientMapInstance.SetClient(tlsConn.LocalAddr().String(), client)
			go UdpStateProcess(client, clientAddr)

		}

		client.Ch <- buffer
	}
}

func UdpStateProcess(client *global.Client, clientAddr *net.UDPAddr) {
	defer func() {
		if r := recover(); r != nil {
			log.Println("StateProcess:", r)
		}
		global.ClientMapInstance.DestroyClient(clientAddr.String())
		global.ClientMapInstance.DestroyClient(client.TLSConn.LocalAddr().String())
	}()

	// pre start
	client.State = global.S_PRE_START

	for {
		buffer := make([]byte, 2048)

		// read base packet
		select {
		case buffer = <-client.Ch:
		case <-time.After(1 * time.Minute):
			return
		}

		var reqTLSPayload []byte
		var respTLSPayload []byte

		// extract base packet
		reqBP := protocol.BasePacket{}
		reqBP.UnMarshal(buffer)

		// opcode & keg id
		opcode := protocol.GetOpcodeByType(reqBP.Type)
		keyId := protocol.GetKeyIDByType(reqBP.Type)

		// check opcode
		if opcode > protocol.P_LAST_OPCODE || opcode <= 0 {
			log.Println("Error Opcode :" + strconv.Itoa(int(opcode)))
			continue
		}

		// extract control packet
		if opcode == protocol.P_CONTROL_HARD_RESET_CLIENT_V2 ||
			opcode == protocol.P_CONTROL_HARD_RESET_CLIENT_V3 ||
			opcode == protocol.P_CONTROL_V1 || opcode == protocol.P_ACK_V1 {
			cp := protocol.ControlPacket{}
			reqBP.Payload = &cp
			cp.UnMarshal(buffer[2+1:], opcode)
			// set sid
			if cp.SessionID > 0 {
				client.RemoteSessionID = cp.SessionID
			}
			// set tls payload
			reqTLSPayload = cp.TLSPayload

		} else if opcode == protocol.P_DATA_V1 || opcode == protocol.P_DATA_V2 { // unprocess
			continue
		} else {
			continue
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
			client.LocalSessionID = binary.LittleEndian.Uint64(protocol.RandBytes(8))
		}

		// skip resp P_ACK_V1
		if opcode == protocol.P_ACK_V1 {
			continue
		}

		// decrypt data
		if len(reqTLSPayload) > 0 {
			// tls req packet
			client.TLSConn.Write(reqTLSPayload)

			// tls resp packet
			tlsPayloadLength, err := client.TLSConn.Read(buffer)
			if err != nil {
				return
			}

			// tls resp overlay openvpn
			respTLSPayload = buffer[:tlsPayloadLength]
			log.Println("[OpenVPN] tls resp packet:", tlsPayloadLength, respTLSPayload)
		}

		// generate control packet
		if opcode == protocol.P_CONTROL_HARD_RESET_CLIENT_V2 ||
			opcode == protocol.P_CONTROL_HARD_RESET_CLIENT_V3 ||
			opcode == protocol.P_CONTROL_V1 || opcode == protocol.P_ACK_V1 {

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
			resp := respBP.Marshal(payload)
			client.CliConn.(*net.UDPConn).WriteToUDP(resp, clientAddr)
		} else if opcode == protocol.P_DATA_V1 || opcode == protocol.P_DATA_V2 { // unprocess
			continue
		} else {
			continue
		}
		client.SendPacketIDCount += 1
	}
}
