# Example exercising hello module

Simple go program that prints its pid and spams `sys_enter_write` so it can be picked up by our Hello module.

Run:
```
go run main.go
```

Producing example output (pid will likely differ):
```
Starting write spammer. PID=7355
tick at 2026-04-06T13:49:46.437083309Z (pid=7355)
tick at 2026-04-06T13:49:46.93704656Z (pid=7355)
tick at 2026-04-06T13:49:47.437048143Z (pid=7355)
...
```

As this is running, we can start our agent that configures a HelloModule with this pid. And while both processes are running, we can check that the module's BPF program is loaded and doing its thing by checking:
```
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep "write by pid"
```

We should only see the lines relevant to our PID, firing every half a second.

If no output is observed, we may need to enable the tracing subsystem first:
```
sudo sh -c 'echo 1 > /sys/kernel/debug/tracing/tracing_on'
```