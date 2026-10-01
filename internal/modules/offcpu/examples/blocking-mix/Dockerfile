FROM ubuntu:24.04 AS build

RUN apt-get update && apt-get install -y gcc libc6-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY main.c .

# Frame pointers - including in leaf functions - so the kernel can walk the
# user stack. The binary isn't stripped, so its symbols can be resolved.
RUN gcc -O2 -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -pthread -o blocking-mix main.c

# Ubuntu (24.04+) builds its packages, glibc included, with frame pointers
# too, so stacks don't break off inside libc.
FROM ubuntu:24.04

COPY --from=build /app/blocking-mix /usr/local/bin/blocking-mix

CMD ["blocking-mix"]
