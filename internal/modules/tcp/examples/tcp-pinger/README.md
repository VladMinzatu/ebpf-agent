# Example exercising the tcp module

A minimal Go program that runs an HTTP server on `:8080` and, every 3s,
makes one request to itself (`http://127.0.0.1:8080/`) and one to
`http://example.com/`. Keep-alives are disabled, so every request opens
and closes its own connection. Each cycle therefore produces:

- the local request: a `connect` (client side), an `accept` (server side)
  and two `close`s (one per end) - both ends are in the same container, so
  both are traced
- the remote request: a `connect` and a `close`

## Run it

```
docker build -t tcp-pinger .
docker run -d --name tcp-pinger tcp-pinger
docker logs -f tcp-pinger
```

```
Starting tcp pinger. PID=1
GET http://127.0.0.1:8080/: 200 OK (5 bytes)
GET http://example.com/: 200 OK (559 bytes)
...
```

## Get its container ID

```
docker inspect -f '{{.Id}}' tcp-pinger
```

A short prefix (e.g. the first 12 characters) is normally enough.

## Run tcp against it

From the repo root (assuming `make docker-build` was run before):
```
sudo make docker-run ARGS="tcp -container <id>"
```

Expect one burst of events every 3s:
```json
{"Module":"tcp","Timestamp":"2026-09-27T14:27:33.094484391Z","Data":{"comm":"tcp-pinger","daddr":"127.0.0.1","dport":8080,"pid":74515,"saddr":"127.0.0.1","sport":58388,"type":"connect"}}
{"Module":"tcp","Timestamp":"2026-09-27T14:27:33.094518849Z","Data":{"comm":"tcp-pinger","daddr":"127.0.0.1","dport":58388,"pid":74515,"saddr":"127.0.0.1","sport":8080,"type":"accept"}}
{"Module":"tcp","Timestamp":"2026-09-27T14:27:33.094977433Z","Data":{"bytes_acked":140,"bytes_received":114,"comm":"tcp-pinger","daddr":"127.0.0.1","dport":58388,"pid":74515,"saddr":"127.0.0.1","sport":8080,"type":"close"}}
{"Module":"tcp","Timestamp":"2026-09-27T14:27:33.095250183Z","Data":{"bytes_acked":115,"bytes_received":141,"comm":"tcp-pinger","daddr":"127.0.0.1","dport":8080,"pid":74515,"saddr":"127.0.0.1","sport":58388,"type":"close"}}
{"Module":"tcp","Timestamp":"2026-09-27T14:27:33.100334312Z","Data":{"comm":"tcp-pinger","daddr":"104.20.23.154","dport":80,"pid":74515,"saddr":"192.168.215.2","sport":36930,"type":"connect"}}
{"Module":"tcp","Timestamp":"2026-09-27T14:27:33.129015041Z","Data":{"bytes_acked":112,"bytes_received":699,"comm":"tcp-pinger","daddr":"104.20.23.154","dport":80,"pid":74515,"saddr":"192.168.215.2","sport":36930,"type":"close"}}
```

The `pid` is the host PID, not the in-container PID 1. The two local
`close`s mirror each other: what one end got acked, the other received.

Only report accepts:
```
sudo make docker-run ARGS="tcp -container <id> -events accept"
```

## Cleanup

```
docker rm -f tcp-pinger
```
