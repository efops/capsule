// A Python web service with a volume for its data.
//   sh examples/build.sh python-web dev.key
//   sudo capsule run -publish 127.0.0.1:8000:8000 examples/out/pyweb
//   curl http://127.0.0.1:8000/
capsule: {
	name: "pyweb"
	command: ["/opt/python/bin/python3", "/app/app.py"]
	env: {
		PYTHONUNBUFFERED:        "1"
		PYTHONDONTWRITEBYTECODE: "1" // the root filesystem is read-only
	}
	publish: [8000]
	volumes: [{name: "data", path: "/data"}]
	limits: {memory: "128M", cpus: 1, pids: 64}
}
rootfs: {
	from: "../.cache/alpine.tar.gz"
	add: [
		{from: "../.cache/python.tar.gz", to: "/opt"}, // unpacks as /opt/python
	]
	files: "/app/app.py": source: "app.py"
}
