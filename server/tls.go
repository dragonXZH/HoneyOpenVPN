package server

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"openvpnHoney/global"
	"openvpnHoney/protocol"
	"os"
	"strconv"
	"time"
)

func TLSClient() net.Conn {
	conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(global.TLSPort))
	if err != nil {
		//log.Println("GenerateTLSConn error:", err)
		return nil
	}
	return conn
}

func TLSServer() {
	// ca
	caCert, err := os.ReadFile(global.CACert)
	if err != nil {
		log.Fatalf("tls: failed to read CA certificate %s", err)
		return
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// server cert
	cert, err := tls.LoadX509KeyPair(global.ServerCert, global.ServerKey)
	if err != nil {
		log.Fatalf("tls: loadkeys: %s", err)
		return
	}
	config := tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS10,
	}
	config.Rand = rand.Reader
	service := "127.0.0.1:" + strconv.Itoa(global.TLSPort)

	// server
	listener, err := tls.Listen("tcp", service, &config)
	if err != nil {
		log.Printf("[OpenVPN] tls decrypt server active")
		return
	}
	//log.Print("server: listening")
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[OpenVPN] tls decrypt accept error")
			break
		}
		go HandleClient(conn)
	}
}

func HandleClient(conn net.Conn) {
	defer func() {
		_ = conn.Close()
		if r := recover(); r != nil {
			//log.Printf("[OpenVPN] %s tls decrypt accept error",conn.RemoteAddr().String())
		}
	}()

	// client
	client := global.ClientMapInstance.GetClient(conn.RemoteAddr().String())

	for {
		buf := make([]byte, 2048)
		// plaintext of control
		n, err := conn.Read(buf)
		if err != nil {
			//log.Printf("[OpenVPN] %s tls decrypt read error %s", conn.RemoteAddr().String())
			return
		}
		//log.Printf("[OpenVPN] %s tls decrypt read: %d", conn.RemoteAddr().String(), buf[:n])

		// unmarshal plaintext
		if client.State < global.S_GENERATED_KEYS {
			k2Req := protocol.InitReqKeyMethod2HandShakeTLSPayload()
			k2Req.UnMarshal(buf[:n])
			log.Printf("[OpenVPN] %s auth username: %s password:%s",
				client.CliConn.RemoteAddr().String(), k2Req.UserNameString, k2Req.PasswordString)
			client.State = global.S_GOT_KEY

			// auth username/password fail
			if len(global.Username) == 0 && len(global.Password) == 0 &&
				(global.Username != k2Req.UserNameString || global.Password != k2Req.PasswordString) {
				plain, cmd := protocol.AuthFailedTlsPayload()
				log.Printf("[OpenVPN] %s auth fail", client.CliConn.RemoteAddr().String())
				conn.Write(plain)
				conn.Write(cmd)
				time.Sleep(1 * time.Second)
				return
			} else {
				log.Printf("[OpenVPN] %s auth succ", client.CliConn.RemoteAddr().String())
			}

			log.Printf("[OpenVPN] %s options: %s", client.CliConn.RemoteAddr().String(), k2Req.OpString)
			log.Printf("[OpenVPN] %s peerinfo: %s", client.CliConn.RemoteAddr().String(), k2Req.PeerInfoString)

			// auth username/password succ
			plain, _ := protocol.AuthFailedTlsPayload()
			conn.Write(plain)
			replay := protocol.PushReply()
			conn.Write(replay)

			client.State = global.S_SENT_KEY
		}

		// ACTIVE

		// data channel
	}

}