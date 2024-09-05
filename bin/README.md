# Bins

Demos, and samples featuring libdaq as wire intercept.

1. net\_echo 

 * Impelements `inject_relative` to echo all received packets.


2. flood

   Floods the network with new flows.

   The new flows will reset after the `-l N` count is reached, then, starts
   over.
 
    ```
    build/flood \
        -e 15 \
        -i eth0 \
        -D 02:42:4b:b5:46:d5 \
        --src-ip 172.17.0.2 \
        --dst-ip 192.168.2.2 \
        -l 3000000 &> /dev/null
    ```

3. dnshog
