# ndisdump

A no-dependencies network packet capture tool for Windows.

## Introduction

Windows systems come with a pre-installed network filter, ndiscap.sys,
which is used by `netsh trace` command to perform network captures
into an .etl file. The file which must then be converted to .pcapng with
another tool.

This repository contains `ndisdump`, a tool that uses ndiscap.sys
to perform network capture directly into .pcapng file.

```
Usage: ndisdump [-s SNAPLEN] -w FILE

-w FILE      The name of the output .pcapng file.
-s SNAPLEN   Truncate packets to SNAPLEN to save disk space.
```

You can terminate the capture with Ctrl+C.

## TODO

The ultimate aim is for this tool to have the same command-line interface
as `tcpdump`, including the filter language.
