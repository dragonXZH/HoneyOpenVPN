package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"log"
)

// protocol state
const (
	P_KEY_ID_MASK  = 0x07
	P_OPCODE_SHIFT = 3

	/* packet opcodes -- the V1 is intended to allow protocol changes in the future */
	P_CONTROL_HARD_RESET_CLIENT_V1 = 1 /* initial key from client, forget previous state */
	P_CONTROL_HARD_RESET_SERVER_V1 = 2 /* initial key from server, forget previous state */
	P_CONTROL_SOFT_RESET_V1        = 3 /* new key, graceful transition from old to new key */
	P_CONTROL_V1                   = 4 /* control channel packet (usually TLS ciphertext) */
	P_ACK_V1                       = 5 /* acknowledgement for packets received */
	P_DATA_V1                      = 6 /* data channel packet */
	P_DATA_V2                      = 9 /* data channel packet with peer-id */

	/* indicates key_method >= 2 */
	P_CONTROL_HARD_RESET_CLIENT_V2 = 7 /* initial key from client, forget previous state */
	P_CONTROL_HARD_RESET_SERVER_V2 = 8 /* initial key from server, forget previous state */

	/* indicates key_method >= 2 and client-specific tls-crypt key */
	P_CONTROL_HARD_RESET_CLIENT_V3 = 10 /* initial key from client, forget previous state */

	/* Variant of P_CONTROL_V1 but with appended wrapped key
	 * like P_CONTROL_HARD_RESET_CLIENT_V3 */
	P_CONTROL_WKC_V1 = 11

	/* define the range of legal opcodes
	 * Since we do no longer support key-method 1 we consider
	 * the v1 op codes invalid */
	P_FIRST_OPCODE = 3
	P_LAST_OPCODE  = 11

	/*
	 * Define number of buffers for send and receive in the reliability layer.
	 */
	TLS_RELIABLE_N_SEND_BUFFERS = 6 /* also window size for reliability layer */
	TLS_RELIABLE_N_REC_BUFFERS  = 12
)

type BasePacket struct {
	Length  uint16
	Type    uint8
	Payload interface{}
}

func (b *BasePacket) UnMarshal(buffer []byte) {
	b.Length = binary.BigEndian.Uint16(buffer[:2])
	b.Type = buffer[2]
}

func (b *BasePacket) Marshal(payload []byte) []byte {
	buffer := make([]byte, 2+1+len(payload))
	b.Length = uint16(1 + len(payload))
	binary.BigEndian.PutUint16(buffer[:2], b.Length)
	buffer[2] = b.Type
	copy(buffer[2+1:], payload)
	return buffer
}

type ControlPacket struct {
	SessionID                   uint64
	MessagePacketIDArrayLength  uint8
	MessagePacketIDArrayElement []uint32
	RemoteSessionID             uint64 // no :client P_CONTROL_HARD_RESET_CLIENT_V
	MessagePacketID             uint32 // no :client P_ACK_V1
	TLSPayload                  []byte
}

func GetOpcodeByType(pType uint8) uint8 {
	return pType >> P_OPCODE_SHIFT
}

func GetKeyIDByType(pType uint8) uint8 {
	return pType & P_KEY_ID_MASK
}

func GetTypeByOpcodeAndKeyID(opcode, keyid uint8) uint8 {
	return opcode<<P_FIRST_OPCODE | keyid
}

func RandBytes(num int) []byte {
	buf := make([]byte, num)
	for i := 0; i < 3; i++ {
		_, err := rand.Read(buf)
		if err != nil {
			log.Println("[OpenVPN] RandBytes error")
			continue
		} else {
			break
		}
	}
	return buf
}

func GetRespType(opcode, keyId uint8) uint8 {
	respOpcode := uint8(0)
	switch opcode {
	case P_CONTROL_HARD_RESET_CLIENT_V1:
		respOpcode = P_CONTROL_HARD_RESET_SERVER_V1
	case P_CONTROL_HARD_RESET_CLIENT_V2:
		respOpcode = P_CONTROL_HARD_RESET_SERVER_V2
	case P_CONTROL_V1, P_ACK_V1:
		respOpcode = P_CONTROL_V1
	case P_DATA_V1, P_DATA_V2:
		respOpcode = opcode
	default:
	}
	return GetTypeByOpcodeAndKeyID(respOpcode, keyId)
}

func IsValidPacket(opcode uint8) bool {
	if opcode == P_CONTROL_HARD_RESET_CLIENT_V1 ||
		opcode == P_CONTROL_HARD_RESET_CLIENT_V2 ||
		opcode == P_CONTROL_V1 {
		return true
	}
	return false
}

func (h *ControlPacket) UnMarshal(buff []byte, opcode uint8) {
	index := 0
	// sid
	h.SessionID = binary.BigEndian.Uint64(buff[index : index+8])
	index += 8

	// message array length
	h.MessagePacketIDArrayLength = buff[index]
	index += 1

	// message array
	if h.MessagePacketIDArrayLength > 0 {
		h.MessagePacketIDArrayElement = make([]uint32, h.MessagePacketIDArrayLength)
		for i := 0; i < int(h.MessagePacketIDArrayLength); i++ {
			h.MessagePacketIDArrayElement[i] = binary.BigEndian.Uint32(buff[index : index+4])
			index += 4
		}
	}

	// remote sid
	// only for linux client ?
	//(opcode == P_CONTROL_V1 && h.MessagePacketIDArrayLength > 0)
	if opcode != P_CONTROL_HARD_RESET_CLIENT_V1 &&
		opcode != P_CONTROL_HARD_RESET_CLIENT_V2 &&
		opcode != P_CONTROL_HARD_RESET_CLIENT_V3 &&
		(opcode == P_CONTROL_V1 && h.MessagePacketIDArrayLength > 0) {
		h.RemoteSessionID = binary.BigEndian.Uint64(buff[index : index+8])
		index += 8
	}

	// message id
	if opcode != P_ACK_V1 {
		h.MessagePacketID = binary.BigEndian.Uint32(buff[index : index+4])
		index += 4
	}

	// tls payload
	if index < len(buff) {
		h.TLSPayload = buff[index:]
	}
}

func (h *ControlPacket) Marshal() []byte {
	index := 0
	buffer := make([]byte, 2048)

	// sid
	binary.BigEndian.PutUint64(buffer[index:index+8], h.SessionID)
	index += 8

	// message array length
	buffer[index] = h.MessagePacketIDArrayLength
	index += 1

	// message array
	for i := uint8(0); i < h.MessagePacketIDArrayLength; i++ {
		binary.BigEndian.PutUint32(buffer[index:index+4], h.MessagePacketIDArrayElement[i])
		index += 4
	}

	// remote sid
	if h.RemoteSessionID > uint64(0) {
		binary.BigEndian.PutUint64(buffer[index:index+8], h.RemoteSessionID)
		index += 8
	}

	// message id
	binary.BigEndian.PutUint32(buffer[index:index+4], h.MessagePacketID)
	index += 4

	// tls payload
	if h.TLSPayload != nil {
		copy(buffer[index:], h.TLSPayload)
		index += len(h.TLSPayload)
	}

	return buffer[:index]
}

type KeyMethod2HandShakeTLSPayload struct {
	Literal        [4]byte
	KeyMethod      uint8
	PreMaster      [48]byte // no: server
	Random1        [32]byte
	Random2        [32]byte
	OpLength       uint16 // big end
	OpString       string // server hard coded: V4,dev-type tun,link-mtu 1587,tun-mtu 1500,proto TCPv4_SERVER,auth SHA512,keysize 128,key-method 2,tls-server
	UserNameLength uint16
	UserNameString string // no: server
	PasswordLength uint16
	PasswordString string // no: server
	PeerInfoLength uint16
	PeerInfoString string
}

func InitReqKeyMethod2HandShakeTLSPayload() KeyMethod2HandShakeTLSPayload {
	k2 := KeyMethod2HandShakeTLSPayload{}
	return k2
}

func InitRespKeyMethod2HandShakeTLSPayload() KeyMethod2HandShakeTLSPayload {
	opString := "server hard coded: V4,dev-type tun,link-mtu 1587,tun-mtu 1500,proto TCPv4_SERVER,auth SHA512,keysize 128,key-method 2,tls-server"
	k2 := KeyMethod2HandShakeTLSPayload{
		OpLength: uint16(len(opString)),
		OpString: opString,
	}
	return k2
}

func (k2 *KeyMethod2HandShakeTLSPayload) UnMarshal(buff []byte) {
	index := uint16(0)
	copy(k2.Literal[:], buff[:4])
	index += 4
	k2.KeyMethod = buff[index]
	index += 1
	copy(k2.PreMaster[:], buff[index:index+48])
	index += 48
	copy(k2.Random1[:], buff[index:index+32])
	index += 32
	copy(k2.Random2[:], buff[index:index+32])
	index += 32
	k2.OpLength = binary.BigEndian.Uint16(buff[index : index+2])
	index += 2
	k2.OpString = string(buff[index : index+k2.OpLength-1])
	index += k2.OpLength
	k2.UserNameLength = binary.BigEndian.Uint16(buff[index : index+2])
	index += 2
	k2.UserNameString = string(buff[index : index+k2.UserNameLength-1])
	index += k2.UserNameLength
	k2.PasswordLength = binary.BigEndian.Uint16(buff[index : index+2])
	index += 2
	k2.PasswordString = string(buff[index : index+k2.PasswordLength-1])
	index += k2.PasswordLength
	k2.PeerInfoLength = binary.BigEndian.Uint16(buff[index : index+2])
	index += 2
	k2.PeerInfoString = string(buff[index:])
}

func (k2 *KeyMethod2HandShakeTLSPayload) Marshal() []byte {
	index := uint16(0)
	buff := make([]byte, 2048)

	copy(buff[index:4], k2.Literal[:])
	index += 4
	buff[index] = k2.KeyMethod
	index += 1
	copy(buff[index:index+32], k2.Random1[:])
	index += 32
	copy(buff[index:index+32], k2.Random2[:])
	index += 32
	binary.BigEndian.PutUint16(buff[index:index+2], k2.OpLength)
	index += 2
	copy(buff[index:index+k2.OpLength], k2.OpString)
	//index += k2.OpLength
	//binary.BigEndian.PutUint16(buff[index:index+2], k2.UserNameLength)
	//index += 2
	//binary.BigEndian.PutUint16(buff[index:index+2], k2.PasswordLength)
	//index += 2
	binary.BigEndian.PutUint16(buff[index:index+2], k2.PeerInfoLength)
	index += 2
	copy(buff[index:index+k2.PeerInfoLength], k2.PeerInfoString)
	index += k2.PeerInfoLength

	return buff
}

func AuthFailedTlsPayload() (plain, cmd []byte) {
	plain = []byte{
		0, 0, 0, 0,
		2,
		165, 38, 137, 235, 155, 74, 57, 161, 228, 178,
		25, 81, 1, 102, 15, 187, 162, 6, 123, 18,
		242, 161, 173, 195, 185, 202, 2, 62, 92, 219,
		192, 202, 26, 147, 209, 154, 246, 83, 171, 149,
		124, 182, 42, 92, 22, 7, 75, 54, 14, 141,
		199, 67, 57, 101, 154, 83, 8, 227, 7, 156,
		240, 126, 24, 49,
		0, 110,
		86, 52,
		44, 100, 101, 118, 45, 116, 121, 112, 101, 32, 116, 117, 110,
		44, 108, 105, 110, 107, 45, 109, 116, 117, 32, 49, 53, 56, 55,
		44, 116, 117, 110, 45, 109, 116, 117, 32, 49, 53, 48, 48,
		44, 112, 114, 111, 116, 111, 32, 84, 67, 80, 118, 52, 95, 83, 69, 82, 86, 69, 82,
		44, 97, 117, 116, 104, 32, 83, 72, 65, 53, 49, 50,
		44, 107, 101, 121, 115, 105, 122, 101, 32, 49, 50, 56,
		44, 107, 101, 121, 45, 109, 101, 116, 104, 111, 100, 32, 50,
		44, 116, 108, 115, 45, 115, 101, 114, 118, 101, 114, 0, 0, 0, 0, 0, 0, 0}
	cmd = []byte{65, 85, 84, 72, 95, 70, 65, 73, 76, 69, 68, 0}
	return plain, cmd
}

func PushReply() []byte {
	return []byte{80, 85, 83, 72, 95, 82, 69, 80, 76, 89, 44, 114, 101, 100, 105, 114, 101, 99, 116, 45, 103, 97, 116, 101, 119, 97, 121, 32, 100, 101, 102, 49, 32, 98, 121, 112, 97, 115, 115, 45, 100, 104, 99, 112, 44, 100, 104, 99, 112, 45, 111, 112, 116, 105, 111, 110, 32, 68, 78, 83, 32, 49, 56, 51, 46, 54, 48, 46, 56, 51, 46, 49, 57, 44, 100, 104, 99, 112, 45, 111, 112, 116, 105, 111, 110, 32, 68, 78, 83, 32, 49, 56, 51, 46, 54, 48, 46, 56, 50, 46, 57, 56, 44, 98, 108, 111, 99, 107, 45, 111, 117, 116, 115, 105, 100, 101, 45, 100, 110, 115, 44, 114, 111, 117, 116, 101, 45, 103, 97, 116, 101, 119, 97, 121, 32, 49, 48, 46, 56, 46, 48, 46, 49, 44, 116, 111, 112, 111, 108, 111, 103, 121, 32, 115, 117, 98, 110, 101, 116, 44, 112, 105, 110, 103, 32, 49, 48, 44, 112, 105, 110, 103, 45, 114, 101, 115, 116, 97, 114, 116, 32, 49, 50, 48, 44, 105, 102, 99, 111, 110, 102, 105, 103, 32, 49, 48, 46, 56, 46, 48, 46, 50, 32, 50, 53, 53, 46, 50, 53, 53, 46, 50, 53, 53, 46, 48, 44, 112, 101, 101, 114, 45, 105, 100, 32, 48, 44, 99, 105, 112, 104, 101, 114, 32, 65, 69, 83, 45, 50, 53, 54, 45, 71, 67, 77, 44, 112, 114, 111, 116, 111, 99, 111, 108, 45, 102, 108, 97, 103, 115, 32, 99, 99, 45, 101, 120, 105, 116, 32, 116, 108, 115, 45, 101, 107, 109, 32, 100, 121, 110, 45, 116, 108, 115, 45, 99, 114, 121, 112, 116, 44, 116, 117, 110, 45, 109, 116, 117, 32, 49, 53, 48, 48, 0}
}
