package keyfactor

import "time"

type Agent struct {
	AgentId          string    `json:"AgentId"`
	AgentPoolId      string    `json:"AgentPoolId"`
	ClientMachine    string    `json:"ClientMachine"`
	Username         string    `json:"Username"`
	AgentPlatform    int       `json:"AgentPlatform"`
	Status           int       `json:"Status"`
	EnableDiscover   bool      `json:"EnableDiscover"`
	EnableMonitor    bool      `json:"EnableMonitor"`
	Version          string    `json:"Version"`
	LastSeen         time.Time `json:"LastSeen"`
	Thumbprint       string    `json:"Thumbprint"`
	LegacyThumbprint string    `json:"LegacyThumbprint"`
}
