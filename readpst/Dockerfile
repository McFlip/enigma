# dependency 
# readpst exe built from libpst source
# building from source because I need bug fixes that haven't made it to release yet

# build container
FROM fedora:40 AS readpstbuild

# Install dependancies
RUN dnf groupinstall -y "Development Tools"
RUN dnf install -y autoconf automake autoconf-archive python-devel boost-python3-devel xmlto libtool gettext-devel libgsf-devel doxygen gcc-c++ glibc-gconv-extra

# Get the libpst source code
RUN git clone https://github.com/pst-format/libpst.git
WORKDIR libpst

# Build libpst

# Workaround python issues
RUN cat Makefile.cvs | sed 's/configure/configure --enable-python=no/' > tmp
RUN mv tmp Makefile.cvs
ENV CPLUS_INCLUDE_PATH="$(find /usr/include -name pyconfig.h)"

RUN make -f *cvs
RUN make -C xml all distclean
WORKDIR src
RUN make readpst
RUN ./readpst -V

# production container
FROM fedora:40
COPY --from=readpstbuild /libpst/src/readpst /usr/local/bin/
COPY --from=readpstbuild /usr/lib64/libgsf-1.so.114 /usr/lib64/

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
