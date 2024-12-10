package global

var (
	ServerMode = "tcp"
	ServerPort = 1194
	TLSPort    = 1195
	CACert     = "ca.crt"
	ServerCert = "server.crt"
	ServerKey  = "server.key"
	Username   = ""
	Password   = ""
)

var (
	ClientMapInstance = InitClientMap()
)
