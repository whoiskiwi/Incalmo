# Range (the network under attack)

Local Docker ranges live here. One subdirectory per topology, each with a `docker-compose.yml` and the vulnerable containers.
Starting point: an official Equifax-style mini range (attacker + webserver + database + crown-jewel).

⚠️ Fully isolated: the `internal` network has no external egress; only self-built target machines are attacked.
