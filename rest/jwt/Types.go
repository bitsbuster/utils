package jwt

type ServiceInfo struct {
	ServiceID   uint64 `json:"service"`
	Environment uint8  `json:"env"`
}
