package oauth2

import (
	"errors"
	"net/http"
	"strconv"
	"time"
)

type GrantInfo struct {
	ClientId           string      `json:"client_id"`
	SessionId          string      `json:"session_id"`
	AccessToken        string      `json:"access_token"`
	AccessTokenExpire  int64       `json:"access_token_expire"`
	RefreshToken       string      `json:"refresh_token"`
	RefreshTokenExpire int64       `json:"refresh_token_expire"`
	Data               interface{} `json:"data,omitempty"`
}

type GrantResponse struct {
	Info GrantInfo `json:"info"`
}

type GrantRequest struct {
	Request
	ClientId  string
	GrantCode string
	Scope     []string
}

func NewGrantRequest(r *http.Request) (*GrantRequest, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, err
	}
	req := new(GrantRequest)
	req.Timestamp, _ = strconv.ParseInt(r.FormValue("t"), 10, 64)
	req.Nonce = r.FormValue("nonce")
	req.ClientId = r.FormValue("client_id")
	req.GrantCode = r.FormValue("grant_code")
	return req, nil
}

func (s *Server) GrantFromRequest(r *http.Request) (*GrantResponse, error) {
	request, err := NewGrantRequest(r)
	if err != nil {
		return nil, err
	}
	if s.opt.Verify != nil {
		client, err := s.storage.GetClient(request.ClientId)
		if err != nil {
			return nil, err
		}
		err = s.opt.Verify(client, r.Header, r.Form)
		if err != nil {
			return nil, err
		}
	}
	return s.Grant(request)
}

func (s *Server) Grant(request *GrantRequest) (*GrantResponse, error) {
	client, err := s.storage.GetClient(request.ClientId)
	if err != nil {
		return nil, err
	}
	sessionId, err := s.storage.GetGrantCode(request.GrantCode)
	if err != nil {
		return nil, err
	}
	data, err := client.Grant(request.Scope, sessionId)
	if err != nil {
		return nil, err
	}
	s.storage.RemoveGrantCode(request.GrantCode)

	accessToken, err := s.opt.Generator.GenAccessToken(client, sessionId)
	if err != nil {
		return nil, err
	}
	refreshToken, err := s.opt.Generator.GenRefreshToken(client, sessionId)
	if err != nil {
		return nil, err
	}

	info := GrantInfo{
		ClientId:           client.GetClientId(),
		SessionId:          sessionId,
		AccessToken:        accessToken,
		AccessTokenExpire:  time.Now().Unix() + s.opt.AccessTokenExpire,
		RefreshToken:       refreshToken,
		RefreshTokenExpire: time.Now().Unix() + s.opt.RefreshTokenExpire,
		Data:               data,
	}
	return &GrantResponse{Info: info}, s.storage.SaveGrantInfo(info)
}

type RefreshRequest struct {
	RefreshToken string
}

func (s *Server) Refresh(refreshToken string) (*GrantResponse, error) {
	info, err := s.storage.GetGrantInfoByRefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}
	client, err := s.storage.GetClient(info.ClientId)
	if err != nil {
		return nil, err
	}
	if info.RefreshTokenExpire < time.Now().Unix() {
		return nil, errors.New("expired")
	}
	if err := s.storage.RemoveAccessToken(info.AccessToken); err != nil {
		return nil, err
	}
	if err := s.storage.RemoveRefreshToken(info.RefreshToken); err != nil {
		return nil, err
	}
	info.AccessToken, err = s.opt.Generator.GenAccessToken(client, info.SessionId)
	info.AccessTokenExpire = time.Now().Unix() + s.opt.AccessTokenExpire
	info.RefreshToken, err = s.opt.Generator.GenRefreshToken(client, info.SessionId)
	info.RefreshTokenExpire = time.Now().Unix() + s.opt.RefreshTokenExpire
	err = s.storage.SaveGrantInfo(info)
	return &GrantResponse{Info: info}, err
}

func (s *Server) VerifyAccessToken(accessToken string) (*GrantResponse, error) {
	info, err := s.storage.GetGrantInfoByAccessToken(accessToken)
	if err != nil {
		return nil, err
	}
	if info.AccessTokenExpire < time.Now().Unix() {
		return nil, errors.New("expired")
	}
	return &GrantResponse{Info: info}, nil
}
