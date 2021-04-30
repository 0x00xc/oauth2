package oauth2

type Client interface {
	GetClientId() string
	GetSecret() string
	Callback() []string
	Grant(scope []string, sessionId string) (interface{}, error)
}
