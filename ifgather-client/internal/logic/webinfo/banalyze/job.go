package banalyze

// resultApp 指纹识别结果
type ResultApp struct {
	Name        string   `json:"name"`
	Version     []string `json:"version"`
	Implies     []string `json:"implies"`
	Description string   `json:"description"`
}
