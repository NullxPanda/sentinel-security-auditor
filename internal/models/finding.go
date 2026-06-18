package models

// Finding is one security signal from the Go hardening layer.
// In Go we use structs instead of Python dataclasses — fields are typed,
// and we attach behavior with methods on the type.
type Finding struct {
	ID             string   `json:"id"`
	Category       string   `json:"category"`
	Severity       string   `json:"severity"`
	File           string   `json:"file,omitempty"`
	Signal         string   `json:"signal,omitempty"`
	Description    string   `json:"description"`
	Recommendation string   `json:"recommendation,omitempty"`
	Tags           []string `json:"tags,omitempty"`
}