package uname

type Info struct {
	Sysname  string
	Nodename string
	Release  string
	Version  string
	Machine  string
}

func GenInfo() (*Info, error) {
	return &Info{}, nil
}
