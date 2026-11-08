// Package protocol holds the spoke<->hub wire types.
package protocol

import "agenttrap/internal/worldpack"

// Bundle is what an operator hands to a new spoke. The token is single-use and
// short-lived; the CA and pack key let the spoke pin the hub and verify packs.
type Bundle struct {
	SpokeID       string `json:"spoke_id"`
	HubURL        string `json:"hub_url"`
	Token         string `json:"token"`
	CAPEM         string `json:"ca_pem"`
	PackPublicKey []byte `json:"pack_public_key"`
}

type EnrollRequest struct {
	Token  string `json:"token"`
	CSRPEM string `json:"csr_pem"`
}

type RenewRequest struct {
	CSRPEM string `json:"csr_pem"`
}

// CertResponse returns a leaf certificate followed by its intermediate.
type CertResponse struct {
	SpokeID string `json:"spoke_id"`
	CertPEM string `json:"cert_pem"`
}

type ConfigResponse struct {
	SpokeID    string             `json:"spoke_id"`
	CanarySeed []byte             `json:"canary_seed"`
	Pack       worldpack.Envelope `json:"pack"`
}

type IngestResponse struct {
	Accepted int `json:"accepted"`
}
