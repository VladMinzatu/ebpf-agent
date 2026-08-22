# Example exercising the hello module

A minimal Go program that prints its PID and spams the `write` syscall
(via `os.Stdout.Write`) every 500ms. It's packaged as its own container so
it has a container-visible PID to test `hello` against.

## Run it

```
docker build -t hello-go-writer .
docker run -d --name hello-go-writer --pid=host hello-go-writer
docker logs -f hello-go-writer
```

```
Starting write spammer. PID=71564
tick at 2026-08-22T10:03:06.528483652Z (pid=71564)
tick at 2026-08-22T10:03:07.028484402Z (pid=71564)
tick at 2026-08-22T10:03:07.528484068Z (pid=71564)
tick at 2026-08-22T10:03:08.028484277Z (pid=71564)
...
```

## Find its PID

```
docker inspect -f '{{.State.Pid}}' hello-go-writer
```

## Run hello against it

From the repo root:
```
make docker-run ARGS="hello -target-pid <pid>"
```

Expect one JSON line per write while both containers are up, e.g.:
```json
{"Module":"hello","Timestamp":"2026-08-22T09:44:10.361998Z","Data":{"comm":"writer","pid":62053}}
```

## Cleanup

```
docker rm -f hello-go-writer
```
