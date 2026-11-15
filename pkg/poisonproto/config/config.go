// Package config defines the subscription-delivered configuration schema
// (ТЗ раздел 14). Every tunable that affects masking, shaping, session
// budgets, etc. lives here and is loaded from JSON — never hard-coded —
// per ТЗ раздел 3, принцип 3.
package config

import (
	"encoding/json"
	"fmt"
	"io"
)

// Config is the top-level subscription document.
type Config struct {
	Version     int         `json:"version"`
	UserTokenID string      `json:"user_token_id"`
	Servers     []Server    `json:"servers"`
	Fingerprint Fingerprint `json:"fingerprint"`
	Session     SessionCfg  `json:"session"`
	Shaping     ShapingCfg  `json:"shaping"`
}

type Server struct {
	ID           string   `json:"id"`
	Addr         string   `json:"addr"`
	Port         int      `json:"port"`
	ServerPubkey string   `json:"server_pubkey"` // X25519, base64
	FallbackSNI  []string `json:"fallback_sni"`
	Transports   []string `json:"transports"`
	Relay        string   `json:"relay,omitempty"`
}

// Ext51764 configures generation of the Yandex 0xCA34 extension (ТЗ 5.7).
type Ext51764 struct {
	Prefixes    []string `json:"prefixes"`
	BaseVariant string   `json:"base_variant"` // hex of variant 1, used as the structural template
	RotateDays  [2]int   `json:"rotate_days"`  // [min,max] days before regenerating per-device value
}

type Fingerprint struct {
	Profile        string     `json:"profile"` // "yandex-android", "yandex-windows", ...
	Ext51764       Ext51764   `json:"ext51764"`
	EchPayloadLens []int      `json:"ech_payload_lens"`
	PSKShare       [2]float64 `json:"psk_share"` // [min,max] fraction of connections using PSK resumption
}

type SessionCfg struct {
	PoolSize        [2]int `json:"pool_size"`
	ConnBudgetBytes [2]int `json:"conn_budget_bytes"`
	Adaptive        bool   `json:"adaptive"`
	AckTimeoutMs    [2]int `json:"ack_timeout_ms"`
}

type ShapingCfg struct {
	Level    string   `json:"level"` // off | light | full
	Profiles []string `json:"profiles"`
}

// Parse decodes a Config from JSON and validates required fields.
func Parse(r io.Reader) (*Config, error) {
	var c Config
	if err := json.NewDecoder(r).Decode(&c); err != nil {
		return nil, fmt.Errorf("config: decode: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) Validate() error {
	if c.Version != 1 {
		return fmt.Errorf("config: unsupported version %d", c.Version)
	}
	if len(c.Servers) == 0 {
		return fmt.Errorf("config: no servers")
	}
	for i, s := range c.Servers {
		if s.Addr == "" || s.Port == 0 || s.ServerPubkey == "" {
			return fmt.Errorf("config: server[%d] (%s) missing addr/port/server_pubkey", i, s.ID)
		}
		if len(s.FallbackSNI) == 0 {
			return fmt.Errorf("config: server[%d] (%s) has no fallback_sni", i, s.ID)
		}
	}
	if c.Session.PoolSize[0] <= 0 || c.Session.PoolSize[1] < c.Session.PoolSize[0] {
		return fmt.Errorf("config: invalid session.pool_size")
	}
	if c.Session.ConnBudgetBytes[0] <= 0 || c.Session.ConnBudgetBytes[1] < c.Session.ConnBudgetBytes[0] {
		return fmt.Errorf("config: invalid session.conn_budget_bytes")
	}
	return nil
}
