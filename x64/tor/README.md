Portable Tor

# WARNING

This binary is not recommended for every day use. It doesn't have the same security features of the standard Tor instance.
It's best use case is if you want to quickly reach to Tor network so you can download the "real" repo. 

# Use

- copy all three files to /opt/tor
- run tor via
```bash
$ cd /opt/tor
$ sudo ./tor -f torrc
```

# As a systemd service
```
[Unit]
Description= tor
After=network.target

[Service]

ExecStart=/opt/tor/tor -f torrc
Restart=always
WorkingDirectory=/opt/tor
User=tor
# remember to create a tor user

[Install]
WantedBy=multi-user.target
```

