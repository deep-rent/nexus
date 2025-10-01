package jwt

type header struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

func (h *header) Algorithm() string { return h.Alg }
func (h *header) KeyID() string     { return h.Kid }
