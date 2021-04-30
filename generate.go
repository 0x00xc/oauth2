package oauth2

import (
	"encoding/hex"
	"math/rand"
)

type Generator interface {
	GenGrantCode(c Client, sessionId string) (string, error)
	GenAccessToken(c Client, sessionId string) (string, error)
	GenRefreshToken(c Client, sessionId string) (string, error)
}

type SimpleGenerator struct{}

func (g *SimpleGenerator) GenGrantCode(c Client, sessionId string) (string, error) {
	return g.randString()
}

func (g *SimpleGenerator) GenAccessToken(c Client, sessionId string) (string, error) {
	return g.randString()
}

func (g *SimpleGenerator) GenRefreshToken(c Client, sessionId string) (string, error) {
	return g.randString()
}

func (g *SimpleGenerator) randString() (string, error) {
	buf := make([]byte, 16)
	rand.Read(buf)
	return hex.EncodeToString(buf), nil
}

func NewSimpleGenerator() *SimpleGenerator {
	return &SimpleGenerator{}
}
