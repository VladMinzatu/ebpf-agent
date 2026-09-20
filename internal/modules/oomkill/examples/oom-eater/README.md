# Example exercising the oomkill module

A minimal Go program that allocates memory 10MB at a time, touching every
page so it counts toward RSS, until the kernel OOM-kills it. It waits 15s
on startup before allocating, so there's a window to attach `oomkill`
before the kill happens. Packaged as its own container and run with a
memory limit, so `oomkill` has a real container to target.

## Run it

```
docker build -t oomkill-eater .
docker run -d --name oomkill-eater --memory=50m oomkill-eater
docker logs -f oomkill-eater
```

```
Starting memory eater. PID=1
Waiting 15s before allocating, so there's time to attach the oomkill module
allocated 10MB total (pid=1)
allocated 20MB total (pid=1)
allocated 30MB total (pid=1)
...
allocated 90MB total (pid=1)
```

The container then exits once the kernel OOM-kills it - past the 50MB
limit set above, since cgroup memory accounting gives it some slack over
the raw bytes touched; exactly how many lines print before that varies
between runs. Confirm it with:

```
docker inspect -f '{{.State.OOMKilled}}' oomkill-eater
```

## Get its container ID

```
docker inspect -f '{{.Id}}' oomkill-eater
```

A short prefix (e.g. the first 12 characters) is normally enough.

## Run oomkill against it

`oomkill` resolves the container ID to a cgroup ID while the container is
still running, so it needs to be attached during the 15s startup window -
run this right after the two commands above (re-`docker run` a fresh
container if the window closes).

From the repo root (assuming `make docker-build` was run before):
```
sudo make docker-run ARGS="oomkill -container <id>"
```

Expect one JSON event once the kernel picks the eater as its OOM victim:
```json
{"Module":"oomkill","Timestamp":"2026-09-20T14:18:37.042253502Z","Data":{"comm":"oom-eater","oom_score_adj":0,"pid":30012,"total_vm_pages":1291704}}
```

## Cleanup

```
docker rm -f oomkill-eater
```
