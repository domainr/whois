package types

type Server struct {
	Resolve func(*Request) error
}
