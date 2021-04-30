package oauth2

type Request struct {
	Timestamp int64
	Nonce     string
}

//func (r *Request)read(req *http.Request) {
//	r.Timestamp
//}
