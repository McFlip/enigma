# compile go code
FROM golang:1.20 AS gobuild
WORKDIR /enigma
COPY . .
RUN go build

# production container
FROM fedora:40
COPY --from=localhost/readpst /usr/local/bin/ /usr/local/bin/
COPY --from=localhost/readpst /usr/lib64/libgsf-1.so.114 /usr/lib64/libgsf-1.so.114
COPY --from=gobuild /enigma/enigma /usr/local/bin/

# create a user
RUN useradd -ms /bin/bash forensicator

# create workspace for unpacking pst files
# REFERENCE: https://docs.docker.com/engine/storage/tmpfs/
# remember to run container with --tmpfs /mnt/ramdisk/unpack:U
# you can also create a ram fs on the host with mount -t ramfs ramfs /mnt/ramdisk/
RUN mkdir -p /mnt/ramdisk/unpack && chown forensicator /mnt/ramdisk/unpack

# working directory to mount to host
RUN mkdir /cases && chown forensicator /cases
USER forensicator
WORKDIR /cases

