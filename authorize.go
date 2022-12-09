package oauth2

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

//授权码模式（authorization code）
//简化模式（implicit）
//密码模式（resource owner password credentials）
//客户端模式（client credentials）

type AuthorizeType string

const (
	AuthorizationCode   AuthorizeType = "code"
	Implicit            AuthorizeType = "implicit"
	PasswordCredentials AuthorizeType = "password"
	ClientCredentials   AuthorizeType = "client"
)

type AuthorizeRequest struct {
	Request                   //其他公共参数，暂未使用
	RequestType AuthorizeType //授权类型
	ClientId    string        //客户端id
	Redirect    string        //授权回调地址
	State       string        //额外参数
}

type AuthorizeResponse struct {
	ClientId  string   //
	GrantCode string   // 授权码
	State     string   // 额外参数
	redirect  *url.URL // 回调地址
}

func (r *AuthorizeResponse) Redirect() string {
	if r.redirect == nil {
		return ""
	}
	v := r.redirect.Query()
	v.Set("grant_code", r.GrantCode)
	v.Set("state", r.State)
	v.Set("client_id", r.ClientId)
	v.Set("t", strconv.Itoa(int(time.Now().Unix())))
	v.Set("nonce", "")
	r.redirect.RawQuery = v.Encode()
	return r.redirect.String()
}

func NewAuthorizeRequest(r *http.Request) (*AuthorizeRequest, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, err
	}
	req := new(AuthorizeRequest)
	req.RequestType = AuthorizeType(r.FormValue("type"))
	req.ClientId = r.FormValue("client_id")
	req.State = r.FormValue("state")
	req.Timestamp, _ = strconv.ParseInt(r.FormValue("t"), 10, 64)
	req.Nonce = r.FormValue("nonce")
	req.Redirect = r.FormValue("redirect")
	return req, nil
}

func (s *Server) GetClient(clientID string) (Client, error) {
	return s.storage.GetClient(clientID)
}

func (s *Server) AuthorizeFromRequest(r *http.Request, sessionId string) (*AuthorizeResponse, error) {
	req, err := NewAuthorizeRequest(r)
	if err != nil {
		return nil, err
	}
	if s.opt.Verify != nil {
		client, err := s.storage.GetClient(req.ClientId)
		if err != nil {
			return nil, err
		}
		err = s.opt.Verify(client, r.Header, r.Form)
		if err != nil {
			return nil, err
		}
	}
	return s.Authorize(req, sessionId)
}

// Authorize
// request 授权请求参数
// sessionId 当前用户识别标识，可以是用户id也可以是其他
// 每次生成授权码（grant_code）时，会将 grant_code 与 sessionId 关联保存，确认授权时，会读取出 sessionId 返回给业务端，
// 业务端自行决定 sessionId 用途（一般用作用户标识）
func (s *Server) Authorize(request *AuthorizeRequest, sessionId string) (*AuthorizeResponse, error) {
	client, err := s.storage.GetClient(request.ClientId)
	if err != nil {
		return nil, err
	}
	switch request.RequestType {
	case "", AuthorizationCode:
		return s.authorizeByCode(client, request, sessionId)
	default:
		return nil, errors.New("not support temporarily") //TODO
	}
}

func (s *Server) authorizeByCode(client Client, request *AuthorizeRequest, sessionId string) (*AuthorizeResponse, error) {
	grantCode, err := s.opt.Generator.GenGrantCode(client, sessionId)
	if err != nil {
		return nil, err
	}
	err = s.storage.SaveGrantCode(grantCode, sessionId)
	if err != nil {
		return nil, err
	}
	redirect := request.Redirect
	u, err := url.Parse(redirect)
	if err != nil {
		return nil, err
	}
	if s.opt.CheckRedirect && !checkRedirect(u, client.Callback()) {
		return nil, errors.New("invalid redirect url")
	}

	return &AuthorizeResponse{
		ClientId:  client.GetClientId(),
		GrantCode: grantCode,
		State:     request.State,
		redirect:  u,
	}, nil
}
