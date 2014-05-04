package server

type Server struct {
	URL func(h, q string) (string, error)
}
