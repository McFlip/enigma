# Enigma

## Purpose

eDiscovery tool for bulk decryption of emails in a batch of PST files, written in Go.

This project is a successor to [batch-decipher-pst](https://github.com/McFlip/batch-decipher-pst).

This is a containerized command line tool.

## Dependencies

This depends on `readpst` from the `libpst` tools. The version used is compiled from the git repo source, as there are bug fixes that haven't made it into a release yet. 
See below for how to build `readpst`.
I wanted to use `go-pst` but there is a an issue with `.msg` emails that are attached to other emails. Also, `go-pst` is not thread-safe.
`go-pst` is used for the `getheaders` command, and `readpst` is not required for that command.

## Build

First, build `readpst`.

```bash
cd readpst
buildah bud -t readpst .
```

Next, build the production container.

```bash
cd ..
buildah bud -t enigma .
```

## Prereq

This is not a cracking tool. You will need a legitimate way of obtaining certs and keys from escrow.
Two helper commands are provided to help you identify encrypted emails and custodian cert info.

getsigs
: Search the `sent items` folder for signed emails and get certificate metadata showing dates, certificate authority, etc.

getheaders
: Collect metadata from email headers and identify if the email is encrypted. NOTE: This doesn't recurse into `.msg` attachments it looks 1 level deep.

## Run

If you have sufficient RAM available, mount a tmpfs to the path `/mnt/ramdisk/unpack`.
This path is used by `readpst` as a temp workspace for unpacking PST files into text format for futher processing.
NOTE: This is only available on a Linux host.

Change into your directory with your input files and mount to the path `/cases`.

```bash
podman run -it --rm --tmpfs /mnt/ramdisk/unpack:U -v $(pwd):/cases:Z --userns=keep-id enigma:latest /bin/bash
```

Enigma uses the Cobra Command framework and has help switches `--help`.
It also uses a YAML config file loaded by Viper. An example config with explanations is provided as `config.example.yaml`.

Simply run `enigma` without any sub-commands to get a help overview of how to use the tool.
Help is available for every command, ex. `enigma decipher --help`.
