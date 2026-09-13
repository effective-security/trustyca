package uname

import (
	"golang.org/x/sys/unix"
)

type Info struct {
	Sysname  string
	Nodename string
	Release  string
	Version  string
	Machine  string
}

func intToString(a [256]byte) string {
	var (
		tmp [256]byte
		i   int
	)

	for i = 0; a[i] != 0; i++ {
		tmp[i] = byte(a[i])
	}
	return string(tmp[:i])
}

func GenInfo() (*Info, error) {
	name := unix.Utsname{}
	_ = unix.Uname(&name)
	return &Info{
		Sysname:  intToString(name.Sysname),
		Nodename: intToString(name.Nodename),
		Release:  intToString(name.Release),
		Version:  intToString(name.Version),
		Machine:  intToString(name.Machine),
	}, nil
}
