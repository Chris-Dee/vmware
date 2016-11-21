The **Bracket Computing vCenter Agent** synchronizes virtual machine
properties between your vCenter server and the Bracket Computing service.
The agent runs continuously in the background.  Once a minute (by default),
it pulls virtual machine properties from vCenter API and sends them to the
Bracket service.  This allows you to see VM properties, such as the name,
cluster name, and datacenter name, in the Bracket UI.

## Requirements

In order to use the Bracket service, you must be a registered Bracket
Computing customer.  Email support@brkt.com for more information.

The **vCenter Agent** requires Go 1.6 or later.

## Installation

To install the **vCenter Agent**, set your `GOPATH` and run `go get`.

```
export GOPATH=~/go
go get github.com/brkt/vmware/cmd/brkt-vcenter-agent

```

## Running the vCenter Agent

To run the **vCenter Agent**, point it at your vCenter URL and pass the
token that you use to authenticate with the Bracket service.  You can
pass the vCenter URL via either the `--vcenter-url` command line
option or the `$BRKT_VCENTER_URL` environment variable.

```
$ $GOPATH/bin/brkt-vcenter-agent --vcenter-url 'https://username:password@10.9.1.217/sdk' --token-path ~/keys/yeti.jwt
INFO[0000] Connected to the Bracket service as customer ac5be98d-021a-4c31-8aee-0d90825102aa
INFO[0000] Getting virtual machines from vCenter at 10.9.1.217
INFO[0001] Found 84 VMs.  3 have a MAC address.
INFO[0001] Sending properties for 3 VMs to the Bracket service at api.mgmt.brkt.com
INFO[0001] Sleeping for 1m0s
```

## Usage

```
$ $GOPATH/bin/brkt-vcenter-agent -h
NAME:
   brkt-vcenter-agent - synchronize instance properties between vCenter and the Bracket service.

USAGE:
   brkt-vcenter-agent [global options] command [command options] [arguments...]

VERSION:
   0.9.0

COMMANDS:
     help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --max-consecutive-failures N  Exit after N consecutive failures (default: 5)
   --service-url URL             Bracket service URL (default: "https://api.mgmt.brkt.com")
   --service-verify-cert         Verify the SSL certificate of the Bracket service (default: true)
   --sleep-duration DURATION     Sleep DURATION between connections to vCenter (default: 1m0s)
   --token JWT                   Bracket service auth token (JWT) [$BRKT_TOKEN]
   --token-path PATH             Read Bracket service auth token from PATH
   --vcenter-url URL             vCenter API URL (required, example: https://username:password@host/sdk) [$BRKT_VCENTER_URL]
   --vcenter-verify-cert         Verify the SSL certificate of the vCenter server (default: true)
   --verbose                     Enable verbose logging
   --help, -h                    show help
   --version, -v                 print the version
```
