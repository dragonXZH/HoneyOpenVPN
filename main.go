package main

import (
	"flag"
	"log"
	"openvpnHoney/global"
	"openvpnHoney/server"
	"os"
	"os/signal"
	"syscall"
)

func initConf() {
	mode := flag.String("mode", global.ServerMode, "tcp or udp")
	port := flag.Int("port", global.ServerPort, "server port")
	tport := flag.Int("tlsport", global.TLSPort, "tls port")
	ca := flag.String("ca", global.CACert, "CA certificate")
	cert := flag.String("cert", global.ServerCert, "server cert")
	key := flag.String("key", global.ServerKey, "server key")
	username := flag.String("username", global.Username, "client auth username")
	password := flag.String("password", global.Password, "client auth password")
	flag.Parse()

	global.ServerMode = *mode
	global.ServerPort = *port
	global.TLSPort = *tport
	global.CACert = *ca
	global.ServerCert = *cert
	global.ServerKey = *key
	global.Username = *username
	global.Password = *password
}

func main() {
	initConf()

	go server.TLSServer()
	switch global.ServerMode {
	case "tcp":
		go server.OpenVpnTcpServer()
	case "udp":
		go server.OpenVpnUdpServer()
	default:
		log.Println("mode: tcp or udp")
		return
	}

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)
	<-shutdown
}
