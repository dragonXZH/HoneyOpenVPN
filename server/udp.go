package server

import (
	"encoding/binary"
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
		log.Printf("[OpenVPN] server resolving address: %s", err)
		return
	}

	// listen connect
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Printf("[OpenVPN] server accept error: %s", err)
		return
	}

	// loop
	buffer := make([]byte, 2048)
	for {
		readNum, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("[OpenVPN] %s socket error %s", clientAddr.String(), err)
			continue
		}

		if readNum < 3 {
			continue
		}

		// client
		client := global.ClientMapInstance.GetClient(clientAddr.String())
		if client == nil {
			// tlsConn
			tlsConn := TLSClient(clientAddr.String())
			if tlsConn == nil {
				continue
			}
			log.Printf("[OpenVPN] %s socket create", clientAddr.String())
			client = &global.Client{
				Ch:      make(chan []byte, 100),
				CliAddr: clientAddr.String(),
				TLSAddr: tlsConn.LocalAddr().String(),
				CliConn: conn,
				TLSConn: tlsConn,
				State:   global.S_INITIAL,
			}
			global.ClientMapInstance.SetClient(clientAddr.String(), client)
			global.ClientMapInstance.SetClient(tlsConn.LocalAddr().String(), client)
			go UdpStateProcess(client, clientAddr)

		}

		client.Ch <- buffer[:readNum]
	}
}

func UdpStateProcess(client *global.Client, clientAddr *net.UDPAddr) {
	tlsLocalAddr := client.TLSConn.LocalAddr().String()

	defer func() {
		log.Printf("[OpenVPN] %s socket close", client.CliAddr)
		if r := recover(); r != nil {
			log.Println("StateProcess:", r)
		}
		global.ClientMapInstance.DestroyClient(clientAddr.String())
		global.ClientMapInstance.DestroyClient(tlsLocalAddr)
	}()

	// pre start
	client.State = global.S_PRE_START
	client.TLSConn.SetReadDeadline(time.Now().Add(1 * time.Second))

	for {
		buffer := make([]byte, 2048)

		// read base packet
		select {
		case buffer = <-client.Ch:
		case <-time.After(10 * time.Minute):
			return
		}

		var reqTLSPayload []byte
		var respTLSPayload []byte

		// extract base packet
		reqBP := protocol.BasePacket{}
		reqBP.UdpUnMarshal(buffer)

		// opcode & keg id
		opcode := protocol.GetOpcodeByType(reqBP.Type)
		keyId := protocol.GetKeyIDByType(reqBP.Type)

		// check opcode
		if opcode > protocol.P_LAST_OPCODE || opcode <= 0 {
			log.Println("Error Opcode :" + strconv.Itoa(int(opcode)))
			continue
		}

		// extract control packet
		{
			cp := protocol.ControlPacket{}
			reqBP.Payload = &cp
			cp.UnMarshal(buffer[1:], opcode)
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
			client.LocalSessionID = binary.LittleEndian.Uint64(protocol.RandBytes(8))
		}

		//
		if opcode == protocol.P_ACK_V1 {
			continue
		}

		// decrypt data
		buffer = make([]byte, 2048)
		if len(reqTLSPayload) > 0 {
			if client.State < global.S_SENT_KEY {
				log.Printf("[OpenVPN] %s tls handshake", client.CliAddr)
			}

			// tls req packet
			client.TLSConn.Write(reqTLSPayload)
			//log.Printf("[OpenVPN] tls req packet %d %d", len(reqTLSPayload), reqTLSPayload)

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
			resp := respBP.UdpMarshal(payload)
			client.CliConn.(*net.UDPConn).WriteToUDP(resp, clientAddr)
		}

		client.SendPacketIDCount += 1

	}
}
