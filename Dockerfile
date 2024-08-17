# compile go code
FROM golang:1.20 AS gobuild
WORKDIR /enigma
COPY . .
RUN go build

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
COPY --from=gobuild /enigma/enigma /usr/local/bin/

