# Fake TPP Server


```terminal
$ go run ./test/tpp/...
I0930 18:00:58.750488  174501 main.go:15] "started" url="https://127.0.0.1:35103"

```


```terminal
$ vcert getcred --insecure -u https://127.0.0.1:45817 -t foo --verbose --username user1 --password pass1
vCert: 2022/09/30 18:21:24 Getting credentials...
vCert: 2022/09/30 18:21:24 Got 400 Bad Request status for POST https://127.0.0.1:45817/vedauth/authorize/token
vCert: 2022/09/30 18:21:24 unexpected status code on TPP Authorize. Status: 400 Bad Request
```
