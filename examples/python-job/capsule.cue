// A Python batch job: runs to the end and exits. Its reports are kept in a volume.
//   sh examples/build.sh python-job dev.key
//   sudo capsule run -receipt receipt.json examples/out/pyjob
// The receipt is a host-signed statement of what ran and a hash of what it printed.
capsule: {
	name: "pyjob"
	command: ["/opt/python/bin/python3", "/app/job.py"]
	env: PYTHONDONTWRITEBYTECODE: "1"
	volumes: [{name: "reports", path: "/data"}]
	limits: {memory: "128M", cpus: 1, pids: 32}
}
rootfs: {
	from: "../.cache/alpine.tar.gz"
	add: [{from: "../.cache/python.tar.gz", to: "/opt"}]
	files: "/app/job.py": source: "job.py"
}
