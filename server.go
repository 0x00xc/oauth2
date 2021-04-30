package oauth2

type Server struct {
	opt     *Options
	storage Storage
}

func NewServer(opt *Options, storage Storage) *Server {
	if opt.Generator == nil {
		opt.Generator = NewSimpleGenerator()
	}
	return &Server{opt: opt, storage: storage}
}

func (s *Server) Storage() Storage {
	return s.storage
}

func (s *Server) SetStorage(storage Storage) {
	s.storage = storage
}
