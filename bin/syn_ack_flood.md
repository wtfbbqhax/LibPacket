Stream washing with 3 million flows, repeated

```
    build/syn_ack_flood -i eth0 \
        -D 02:42:4b:b5:46:d5 \
        --src-ip 172.17.0.2 \
        --dst-ip 192.168.2.2 \
        -l 3000000 
        &>/dev/null
```
