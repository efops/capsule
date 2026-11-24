// A Java web service that runs as two to four replicas behind one port.
//   sh examples/build.sh java-web dev.key
//   sudo capsule run -publish 127.0.0.1:8080:8080 examples/out/javaweb
//   curl http://127.0.0.1:8080/        (ask a few times: the replicas take turns)
capsule: {
	name: "javaweb"
	// The JDK runs a single source file directly, so there is no build step here.
	// The capsule cannot see the host's memory limit files, so say how much the JVM may use.
	command: ["/opt/java/bin/java", "-Xmx192m", "-XX:+UseSerialGC", "/app/Hello.java"]
	publish: [8080]
	limits: {memory: "512M", cpus: 1, pids: 256} // a JVM's threads count as processes
	scale: {min: 2, max: 4, cpu: 70, memory_max: "1G"}
}
rootfs: {
	from: "../.cache/alpine.tar.gz"
	add: [
		{from: "../.cache/jdk.tar.gz", to: "/opt/java", strip: 1}, // the archive wraps everything in jdk-21.x/
	]
	files: "/app/Hello.java": source: "Hello.java"
}
