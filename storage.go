package oauth2

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"strings"
)

type Storage interface {
	GetClient(id string) (Client, error)
	SaveGrantCode(code string, sessionId string) error
	GetGrantCode(code string) (string, error)
	RemoveGrantCode(code string) error
	SaveGrantInfo(info GrantInfo) error
	GetGrantInfoByAccessToken(accessToken string) (GrantInfo, error)
	GetGrantInfoByRefreshToken(refreshToken string) (GrantInfo, error)
	RemoveAccessToken(accessToken string) error
	RemoveRefreshToken(refreshToken string) error
}

type SimpleClient struct {
	Id       string
	Secret   string
	Redirect string
}

func (s *SimpleClient) GetClientId() string {
	return s.Id
}

func (s *SimpleClient) GetSecret() string {
	return s.Secret
}

func (s *SimpleClient) Callback() []string {
	return strings.Fields(s.Redirect)
}

func (s *SimpleClient) Grant(scope []string, sessionId string) (interface{}, error) {
	m := make(map[string]interface{})
	h := md5.New()
	h.Write([]byte(s.Id + "@" + sessionId + "@" + s.Id))
	m["open_id"] = hex.EncodeToString(h.Sum(nil))
	return m, nil
}

type SimpleStorage struct {
	clients      KVStorage
	grantCodes   KVStorage
	grantInfo    KVStorage
	refreshToken KVStorage

	getClient func(id string) (Client, error)
}

func NewSimpleStorage(getClient func(id string) (Client, error)) *SimpleStorage {
	return &SimpleStorage{
		clients:      NewSyncMap(),
		grantCodes:   NewSyncMap(),
		grantInfo:    NewSyncMap(),
		refreshToken: NewSyncMap(),
		getClient:    getClient,
	}
}

func NewSimpleKVStorage(getClient func(id string) (Client, error), newKVStorage func() KVStorage) *SimpleStorage {
	return &SimpleStorage{
		clients:      newKVStorage(),
		grantCodes:   newKVStorage(),
		grantInfo:    newKVStorage(),
		refreshToken: newKVStorage(),
		getClient:    getClient,
	}
}

func (s *SimpleStorage) PutClient(c *SimpleClient) {
	s.clients.Put(c.Id, c)
}

func (s *SimpleStorage) RemoveClient(id string) {
	s.clients.Del(id)
}

func (s *SimpleStorage) GetClient(id string) (Client, error) {
	v, err := s.clients.Get(id)
	if err == nil {
		return v.(*SimpleClient), nil
	}
	if s.getClient != nil {
		cli, err := s.getClient(id)
		if err == nil {
			s.clients.Put(id, cli)
		}
		return cli, err
	}
	return nil, errors.New("not found")
}

func (s *SimpleStorage) SaveGrantCode(code string, sessionId string) error {
	return s.grantCodes.Put(code, sessionId)
}

func (s *SimpleStorage) GetGrantCode(code string) (string, error) {
	v, err := s.grantCodes.Get(code)
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

func (s *SimpleStorage) RemoveGrantCode(code string) error {
	return s.grantCodes.Del(code)
}

func (s *SimpleStorage) SaveGrantInfo(info GrantInfo) error {
	s.grantInfo.Put(info.AccessToken, info)
	s.refreshToken.Put(info.RefreshToken, info.AccessToken)
	return nil
}

func (s *SimpleStorage) GetGrantInfoByAccessToken(accessToken string) (GrantInfo, error) {
	v, err := s.grantInfo.Get(accessToken)
	if err != nil {
		return GrantInfo{}, err
	}
	return v.(GrantInfo), nil
}

func (s *SimpleStorage) RemoveAccessToken(accessToken string) error {
	info, err := s.GetGrantInfoByAccessToken(accessToken)
	if err != nil {
		return err
	}
	s.grantInfo.Del(accessToken)
	s.refreshToken.Del(info.RefreshToken)
	return nil
}

func (s *SimpleStorage) GetGrantInfoByRefreshToken(refreshToken string) (GrantInfo, error) {
	v, err := s.refreshToken.Get(refreshToken)
	if err != nil {
		return GrantInfo{}, err
	}
	return s.GetGrantInfoByAccessToken(v.(string))
}

func (s *SimpleStorage) RemoveRefreshToken(refreshToken string) error {
	return s.refreshToken.Del(refreshToken)
}
