# Cert Sub Go

## Description

Cert Sub Go is a tool to query SSL Certificate Transparency for subdomain discovery. The more you are willing to wait,
the further back will this app look in SSL history, which is defined by the "BlockSize" **-s** flag. Default is 1'200'000.
Since google gives back 32 certificates in one chunk, it will be 37'500 GET requests for that SSL Log provider.  
  
The app queries all providers from here ```https://www.gstatic.com/ct/log_list/v3/all_logs_list.json```

### Installation

```bash
go install github.com/elvisgraho/cert-sub-go@latest
```

### Flags

* -r: File with root domains (mandatory), e.g., ```tesla.com```
* -s: Block size, e.g., ```-s 2000000'```. How many SSL entries to scan for each provider. More entries = further back the data.
* -wildCard: FRemove all *. from SSL data.
* -o: Out filename, default is  ```-o cert-sub-go.out```
* -v: Verbose logging

### Examples

```sh
cert-sub-go -r .\targets.txt -wildCard
```

### Credits

Inspired by: [Gungnir](https://github.com/g0ldencybersec/gungnir)
