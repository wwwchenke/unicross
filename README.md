## Prerequisites

Download and install a newer version of Go



##  Running Tests

```
cd Volley
go build
./volley --setup
./volley --thread 16
```



## Components Tests

```
cd lpr
go test -run=^$ -bench=BenchmarkRLWEEncryption
go test -run=^$ -bench=BenchmarkRLWEDecryption
go test -run=^$ -bench=BenchmarkLWEDecryption
```

```
cd protocol
go test -run=^$ -bench=^BenchmarkSetup$
go test -run=^$ -bench=BenchmarkSetupWithPrecomputes
go test -run=^$ -bench=BenchmarkGenProof
go test -run=^$ -bench=BenchmarkVerifyProof
```
