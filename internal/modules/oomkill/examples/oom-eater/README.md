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

## Bonus: Deep dive into the reader mechanism

`oomkill`'s reader blocks in `epoll_pwait` on the ringbuf map's fd until the kernel wakes it - it isn't polling. You can watch that block/wake cycle with `strace`, attached from a throwaway container sharing the agent's PID namespace.

Run `oomkill` in its own terminal exactly as in "Run oomkill against it"
above and leave it running. Then start the agent:
```
sudo make docker-run ARGS="oomkill -container <id>"
```

In another terminal, find that container (`make docker-run` doesn't name it, but it's the only one running the `ebpf-agent` image) and attach to it:
```
agent_cid=$(docker ps --filter ancestor=ebpf-agent --format '{{.ID}}')
docker run --rm -it --pid=container:$agent_cid --cap-add=SYS_PTRACE alpine \
  sh -c 'apk add --no-cache strace >/dev/null && strace -tt -f -e trace=epoll_pwait -p 1'
```

Once the eater gets OOM-killed, we get something like:
```
[pid     8] 17:43:02.590110 epoll_pwait(10 <unfinished ...>
[pid     8] 17:43:17.494338 <... epoll_pwait resumed>, [{events=EPOLLIN, data=0x3}], 1, -1, NULL, 0) = 1
```

That's the reader's OS thread parked in `epoll_pwait` (timeout `-1` = block forever, since the module never sets a deadline) for the ~15s the eater took to get killed, then waking the instant `bpf_ringbuf_submit` in `oomkill.c` notifies it. Note that there is no `read()` following the wakeup - the record is already sitting in the mmap'd ring pages, so retrieving it is plain memory access, invisible to strace.

(It's `epoll_pwait`, not `epoll_wait` - filtering on the latter catches nothing.)

## Cleanup

```
docker rm -f oomkill-eater
```

(`make docker-run` and the `strace` container both run with `--rm`, so
they clean up on their own once stopped.)
