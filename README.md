## A parser and semantic analyzer for SPF, DMARC, and CAA DNS records
### Build Instructions
1. The parser and semantic analyzer are written in Golang.  You must download and install Golang from [here](https://go.dev/dl/) before proceeding.
2. Clone this GitHub repository
3. Run `go install` in the directory to install all depedencies
4. Run `go build` to build the program.  There should be an executable called `dnsScanner` in the current directory if it's compiled correctly.
5. Set the `DNSSCAN_RESOLV_PATH` environmental variable to the path of the `resolv.conf` file.  This file contains the information needed for the DNS library to perform lookups.  There is a example file in this repository that uses `8.8.8.8` to resolve DNS queries.
6.  Run the `dnsScanner` executable.  This spawns an HTTP server that listens at port 10000.  An HTTP get request to `http://localhost:1000/api/{domain}` (where "{domain}" is replaced with the domain to scan) awill return a JSON object with the results.

Feel free to contact me with any questions or issues!