## Installation

1. **Install Go**

Make sure you have a recent version of Go (>= 1.20).

2. **Clone the repository**

```
git clone https://github.com/wwwchenke/unicross.git
cd unicross
```

3. **Build the executable**

```
go build -o unicross
```

This will generate an executable file named `unicross` in the current directory.

---



##  Usage

Run the following command to initialize the test environment:

```
./unicross --setup
```

This will generate a `testdata/` directory in the current folder.

Run the full protocol with 16 threads:

```
./unicross --thread 16
```

#### Optional Parameters

- `--thread`: Number of threads to use (default: `4`)

All communication data between participants will be saved as binary files in their respective folders under `testdata/`.

---



## Components Tests

### RLWE / LWE Components

Navigate to the `lpr/` directory and run:

```
cd lpr
go test -run=^$ -bench=BenchmarkRLWEEncryption
go test -run=^$ -bench=BenchmarkRLWEDecryption
go test -run=^$ -bench=BenchmarkLWEDecryption
```

### Protocol Components

Navigate to the `protocol/` directory and run:

```
cd ../protocol
go test -run=^$ -bench=^BenchmarkSetup$
go test -run=^$ -bench=BenchmarkSetupWithPrecomputes
go test -run=^$ -bench=BenchmarkGenProof
go test -run=^$ -bench=BenchmarkVerifyProof
```

---
