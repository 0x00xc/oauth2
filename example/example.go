package example

import (
	"encoding/json"
	"fmt"
	"github.com/0x00xc/oauth2"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type Example struct {
	server *oauth2.Server
}

func NewExample() *Example {
	e := &Example{}

	opt := oauth2.DefaultOptions()
	storage := oauth2.NewSimpleStorage(nil)
	storage.PutClient(&oauth2.SimpleClient{
		Id:       "1000",
		Secret:   "ab2c9fbe11ecd792e731ca26972416d9",
		Redirect: "http://127.0.0.1:8000/example/callback",
	})

	e.server = oauth2.NewServer(opt, storage)
	return e
}

func (e *Example) Authorize() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		//TODO 登录、身份认证等
		sessionId := r.FormValue("sid")             //正式情况下需要用户认证后再生成id
		request, _ := oauth2.NewAuthorizeRequest(r) //建议自行生成oauth2.AuthorizeRequest，并进行参数校验，接口签名
		data, err := e.server.Authorize(request, sessionId)
		if err != nil { //TODO handle error
			http.Error(w, err.Error(), 500)
			return
		}
		//不建议使用 data.Redirect()
		//正式情况下应该基于 data 自行生成返回数据，包括参数校验，接口签名等
		http.Redirect(w, r, data.Redirect(), http.StatusFound)
	}
}

func (e *Example) Grant() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		request, _ := oauth2.NewGrantRequest(r) //TODO 参数校验 接口签名
		data, err := e.server.Grant(request)
		if err != nil { //TODO handle error
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(data)
	}
}

func (e *Example) Serve(addr string) error {
	http.Handle("/authorize", e.Authorize())
	http.Handle("/grant", e.Grant())

	//正式情况下约定好参数格式后，由第三方提供回调地址，并在回调中调用grant接口
	http.HandleFunc("/example/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("grant_code")
		state := r.URL.Query().Get("state")
		clientId := r.URL.Query().Get("client_id")
		v := url.Values{}
		//v.Set("nonce", "123456")
		v.Set("t", strconv.Itoa(int(time.Now().Unix())))
		v.Set("client_id", clientId)
		v.Set("grant_code", code)
		re, err := http.PostForm("http://127.0.0.1:8000/grant", v)
		if err != nil {
			fmt.Fprintf(w, "%v", err)
			w.WriteHeader(500)
			return
		}
		io.Copy(w, re.Body)
		fmt.Fprintf(w, "\ngrant_code:%s\nstate:%s\n", code, state)
	})
	return http.ListenAndServe(addr, nil)
}
