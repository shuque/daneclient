module github.com/shuque/daneclient

go 1.27

require (
	github.com/shuque/dane/v2 v2.0.0
	golang.org/x/crypto v0.59.0
	golang.org/x/sys v0.50.0
)

require (
	github.com/miekg/dns v1.1.73 // indirect
	golang.org/x/net v0.62.0 // indirect
)

replace github.com/shuque/dane/v2 => ../dane/v2
