# Enigma

This repository is part of [batch-decipher-pst](https://github.com/McFlip/batch-decipher-pst).

The goal of this sub-project is to replace the Bash scripts with Go packages allowing for increased performance and additional capabilities.
This will also allow the tools to be run on Windows after cross-compiling.

## Build

To cross-compile for Windows, assuming same arch on both systems:

```bash
GOOS=windows go build main.go
```
