# Example exercising the hello module

A minimal Go program that prints its PID and spams the `write` syscall
(via `os.Stdout.Write`) every 500ms. It's packaged as its own container so
`hello` has a real container to target.

## Run it

```
docker build -t hello-go-writer .
docker run -d --name hello-go-writer hello-go-writer
docker logs -f hello-go-writer
```

```
Starting write spammer. PID=1
tick at 2026-08-22T13:41:05.395001415Z (pid=1)
tick at 2026-08-22T13:41:05.894998998Z (pid=1)
tick at 2026-08-22T13:41:06.394998456Z (pid=1)
tick at 2026-08-22T13:41:06.895003457Z (pid=1)
tick at 2026-08-22T13:41:07.394998332Z (pid=1)
tick at 2026-08-22T13:41:07.894999415Z (pid=1)
...
```

## Get its container ID

```
docker inspect -f '{{.Id}}' hello-go-writer
```

A short prefix (e.g. the first 12 characters) is normally enough.

## Run hello against it

From the repo root:
```
make docker-run ARGS="hello -container <id>"
```

Expect one JSON line per write while the writer container is up, e.g.:
```json
{"Module":"hello","Timestamp":"2026-08-22T13:42:24.900083405Z","Data":{"comm":"writer","pid":88153}}
{"Module":"hello","Timestamp":"2026-08-22T13:42:25.400526598Z","Data":{"comm":"writer","pid":88153}}
{"Module":"hello","Timestamp":"2026-08-22T13:42:25.897537843Z","Data":{"comm":"writer","pid":88153}}
{"Module":"hello","Timestamp":"2026-08-22T13:42:26.399248643Z","Data":{"comm":"writer","pid":88153}}
{"Module":"hello","Timestamp":"2026-08-22T13:42:26.899542755Z","Data":{"comm":"writer","pid":88153}}
{"Module":"hello","Timestamp":"2026-08-22T13:42:27.397301823Z","Data":{"comm":"writer","pid":88153}}
{"Module":"hello","Timestamp":"2026-08-22T13:42:27.901688456Z","Data":{"comm":"writer","pid":88153}}
{"Module":"hello","Timestamp":"2026-08-22T13:42:28.400271136Z","Data":{"comm":"writer","pid":88153}}
```

## Cleanup

```
docker rm -f hello-go-writer
```
