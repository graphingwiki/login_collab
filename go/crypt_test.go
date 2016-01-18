package main

import (
	"bytes"
	"testing"
)

type testCase struct {
	rounds   uint64
	salt     string
	password string
	result   string
}

// Test cases taken from http://www.akkadia.org/drepper/SHA-crypt.txt.
var cases = [...]testCase{
	{
		5000,
		"saltstring",
		"Hello world!",
		"svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1",
	},
	{
		10000,
		"saltstringsaltstring",
		"Hello world!",
		"OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.",
	},
	{
		5000,
		"toolongsaltstring",
		"This is just a test",
		"lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0",
	},
	{
		1400,
		"anotherlongsaltstring",
		"a very much longer text to encrypt.  This one even stretches over morethan one line.",
		"POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1",
	},
	{
		77777,
		"short",
		"we have a short salt string but not a short password",
		"WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0",
	},
	{
		123456,
		"asaltof16chars..",
		"a short string",
		"BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1",
	},
	{
		10,
		"roundstoolow",
		"the minimum number is still observed",
		"kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX.",
	},
}

func TestCrypt(t *testing.T) {
	for _, c := range cases {
		password := []byte(c.password)
		salt := []byte(c.salt)
		result := []byte(c.result)

		if bytes.Compare(crypt(password, c.rounds, salt), result) != 0 {
			t.Fail()
		}
	}
}
