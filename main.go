// capsule: a daemonless runtime that runs nothing unless it is sealed and trusted.
package main

import (
	"errors"
	"fmt"
	"os"
)

// exitError carries the capsule's own exit status out through main.
type exitError int

func (e exitError) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

const usage = `usage:
  build and sign
    capsule init [-rootfs <dir or tarball>] <dir>
                                             create a capsule: starter manifest and rootfs
    capsule build [-key <file>] [-rules <file.cue>] [-o <dir>] <file.cue>
                                             build (and seal) a capsule from a CUE build file
    capsule render [-o <dir>] <fleet.cue>    lay out a fleet from a CUE file, one directory per host
    capsule publish -key <file> <dir>        upload a sealed capsule to the fleet's shared store
    capsule fetch [-o <dir>] <name>          install the current release of a capsule from it
    capsule keygen <name>                    create <name>.key, <name>.pub and <name>.id
    capsule seal -key <file> [-host <host file>]... <dir>
                                             hash rootfs + manifest and sign them; with policy.hosts
                                             or policy.timelock, also encrypt the rootfs
    capsule approve -key <file> [-days N] <dir>  add one signer's approval to a sealed capsule
    capsule permit -key <file> -host <host id> [-runs N] [-days N] <dir>
                                             let one host run a sealed capsule N times
    capsule verify [-trust <pub>] <dir>      check the seal against trusted keys
    capsule inspect [-trust <pub>] <dir>     describe a capsule and whether this host would run it
    capsule revoke -key <file> [-publish] <dir>
                                             sign a revocation for all hosts: printed for their
                                             revoked.d, or with -publish put in the fleet ledger
    capsule card -key <file> -name <name> -mesh-key <key> [-endpoint ip:port]
                                             vouch that a mesh key is an instance of <name>
    capsule delegate -key <file> -host <signing key id> <name>...
                                             let a host issue its own cards for these names
    capsule grant -key <file> -receptor <name> -of <cell> -to <cell> [-for 24h]
                                             let one cell use a receptor another offers, for a
                                             span of time; put the output in grants.d/ on the
                                             calling cell's host
    capsule tick                             the current tick: the drand beacon's round
  run (Linux)
    capsule run [-trust <pub>] [-publish [addr:]hostport:capsuleport] [-receipt <file>] <dir>
                                             verify, check policy, then run in a kernel sandbox;
                                             with a scale section, keep a set of replicas running
        [-instance <label>]                  a replica with its own volumes and mesh identity
        mesh: [-listen <udp port>] [-advertise <ip>] [-peers <dir>]
    capsule ps                               list running capsules
    capsule kill <id>                        kill every process in a capsule
    capsule resize [-memory 512M] [-cpus 2] [-pids 256] <id>
                                             change a running capsule's limits
  orders: operate hosts without logging in to them
    capsule order -key <file> -host <host file>... [-for 10m] [-wait 30s] [-o <file>] <action>
                                             sign an order and send it through the ledger; actions:
                                             fetch, run, stop, resize, revoke, ps, log, exec
                                             (capsule order -h lists them)
    capsule order sign -key <file> <order file>   add another operator's signature
    capsule order send [-wait 30s] <order file>   send an order written with -o
    capsule order result [-wait 30s] <order file or id>
                                             print the hosts' signed answers
    capsule orders                           on a host: carry out the orders waiting for it
  this host
    capsule host [-export]                   print this host's id and signing key id, or with
                                             -export the host file needed to seal a capsule for it
    capsule identity [-instance <label>] <name>
                                             print the mesh key and address an instance has here
    capsule revoke <dir>                     never run this exact seal on this host again
    capsule log [-host <signing key id>] [-file <copy>] [-ledger]
                                             print the run record and check it is intact; with
                                             -ledger, also against what was published to the fleet
    capsule ledger check                     test whether the configured ledger can be trusted
                                             with fleet-wide run limits
    capsule witness                          publish this host's record to the fleet ledger and
                                             co-sign the other hosts' 
    capsule receipt -host <signing key id> <file>
                                             check a run receipt from another host
    capsule volumes [-rm <name> | -snapshot <name> | -restore <name> <snapshot> | -grant <name> <host file>]
                                             list the data capsules keep here; delete, snapshot
                                             or restore one capsule's, or let another host open
                                             its encrypted volumes
    capsule prune                            delete stored rootfs copies nothing is using

Signatures are Ed25519 plus ML-DSA-65 and key wraps are X25519 plus
ML-KEM-768; both halves must hold. Keys are named by id in manifests.

A capsule is a directory holding capsule.json, capsule.seal and rootfs/ (or
rootfs.enc when it has a host list). Trusted keys are read from
/etc/capsule/trust.d/*.pub, a user's own ~/.config/capsule/trust.d/*.pub and any
-trust flags. Host settings live in
/etc/capsule (or ~/.config/capsule): peers.d/, grants.d/, revoked.d/, delegation,
operators.d/*.pub (whose orders this host obeys) and orders (how many of them
must sign each action),
policy.d/*.cue (rules every capsule run here must satisfy), log-forward (a
URL every log entry is posted to), and ledger (the fleet's shared store: a
file://, s3://, vault:// or artifactory:// URL). Without root, run uses a
user namespace, and mesh and cell tunnels run inside capsule itself.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	args := os.Args[2:]
	var err error
	switch os.Args[1] {
	case "__init": // internal: first process inside the new namespaces
		err = initCapsule()
	case "__enter": // internal: a command joining a running capsule for an exec order
		err = enterCapsule()
	case "__helper": // internal: started as root by systemd for capsule-helper.socket
		err = cmdHelper()
	case "order":
		err = cmdOrder(args)
	case "orders":
		err = cmdOrders(args)
	case "run":
		err = cmdRun(args)
	case "ps":
		err = cmdPs()
	case "kill":
		err = cmdKill(args)
	case "resize":
		err = cmdResize(args)
	case "volumes":
		err = cmdVolumes(args)
	case "prune":
		err = cmdPrune(args)
	case "identity":
		err = cmdIdentity(args)
	case "host":
		err = cmdHost(args)
	case "card":
		err = cmdCard(args)
	case "delegate":
		err = cmdDelegate(args)
	case "grant":
		err = cmdGrant(args)
	case "tick":
		err = cmdTick(args)
	case "approve":
		err = cmdApprove(args)
	case "permit":
		err = cmdPermit(args)
	case "witness":
		err = cmdWitness(args)
	case "ledger":
		err = cmdLedger(args)
	case "revoke":
		err = cmdRevoke(args)
	case "log":
		err = cmdLog(args)
	case "receipt":
		err = cmdReceipt(args)
	case "version":
		fmt.Println("capsule", version)
	case "init":
		err = cmdInit(args)
	case "build":
		err = cmdBuild(args)
	case "render":
		err = cmdRender(args)
	case "publish":
		err = cmdPublish(args)
	case "fetch":
		err = cmdFetch(args)
	case "inspect":
		err = cmdInspect(args)
	case "keygen":
		err = cmdKeygen(args)
	case "seal":
		err = cmdSeal(args)
	case "verify":
		err = cmdVerify(args)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var code exitError
	if errors.As(err, &code) {
		os.Exit(int(code))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "capsule:", err)
		os.Exit(1)
	}
}
