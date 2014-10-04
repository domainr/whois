package whois

import (
	"bufio"
	"fmt"
)

func scan(res *Response) {
	r, err := res.Reader()
	if err != nil {
		return
	}
	line := 0
	s := bufio.NewScanner(r)
	for s.Scan() {
		line++
		fmt.Printf("% 4d %s\n", line, s.Text())
	}
}
