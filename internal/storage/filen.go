package storage

type FilenProvider struct {
	config FilenConfig
}

type FilenConfig struct {
	Email    string
	Password []byte
	BaseURL  string
}

func NewFilenProvider(config FilenConfig) *FilenProvider {
	return &FilenProvider{config: config}
}
