package global

import (
	"net"
	"sync"
)

const (
	S_UNDEF = iota
	S_INITIAL
	S_PRE_START
	S_START
	S_GOT_KEY
	S_SENT_KEY
	S_ACTIVE
	S_GENERATED_KEYS
)

type ClientMap struct {
	sync.RWMutex
	m map[string]*Client
}

func InitClientMap() *ClientMap {
	client := ClientMap{
		m: make(map[string]*Client),
	}
	return &client
}

func (c *ClientMap) SetClient(key string, client *Client) {
	c.Lock()
	defer c.Unlock()
	c.m[key] = client
}

func (c *ClientMap) GetClient(key string) *Client {
	c.Lock()
	defer c.Unlock()
	if client, ok := c.m[key]; !ok {
		return nil
	} else {
		return client
	}
}

func (c *ClientMap) DestroyClient(key string) {
	c.Lock()
	defer c.Unlock()
	if client, ok := c.m[key]; !ok {
		return
	} else {
		client.Destroy()
		delete(c.m, key)
	}
}

type Client struct {
	Ch                chan []byte
	CliAddr           string
	TLSAddr           string
	CliConn           net.Conn
	TLSConn           net.Conn
	State             int
	RemoteSessionID   uint64
	LocalSessionID    uint64
	RecvPacketIDCount uint8
	SendPacketIDCount uint32

	sync.RWMutex
}

func (c *Client) Destroy() {
	c.Lock()
	defer c.Unlock()

	// clear channel
	if c.Ch != nil {
		close(c.Ch)
		c.Ch = nil
	}

	// clear tls conn
	if c.TLSConn != nil {
		_ = c.TLSConn.Close()
		c.TLSConn = nil
	}

	// clear client conn
	if _, ok := c.CliConn.(*net.TCPConn); ok {
		_ = c.CliConn.Close()
	}
	c.CliConn = nil
}
