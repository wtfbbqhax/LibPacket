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

    /volume/libpacket/bin # sudo ./build/flood \
        -e 2 -i eno1 -D 6c:c3:b2:69:7a:f8 --src-ip 192.168.30.4 --dst-ip 192.168.20.2 -l 10


    # Vanilla MX, Vlan 50
    bin # ./build/flood -e 2 -i eno1 -D ac:17:c8:c5:26:a3 --src-ip 192.168.50.5 --dst-ip 192.168.51.3 -l 1

    The packet generation is not as fast as desired

    Test 1

    CONFIG: use_tx_ring = true
            attack_i % 1024
    ```
    vppctl monitor inteface lan

    rx: 0pps 0bps tx: 0pps 0bps
    rx: 0pps 0bps tx: 0pps 0bps
    rx: 0pps 0bps tx: 0pps 0bps
    rx: 2.32Kpps 1.67Mbps tx: 2.32Kpps 1.11Mbps
    rx: 4.79Kpps 3.45Mbps tx: 5.07Kpps 2.44Mbps
    rx: 4.14Kpps 2.98Mbps tx: 4.15Kpps 1.99Mbps
    rx: 4.57Kpps 3.29Mbps tx: 1.54Kpps 739.19Kbps
    rx: 4.64Kpps 3.34Mbps tx: 1pps 959bps
    rx: 4.09Kpps 2.95Mbps tx: 1.81Kpps 867.84Kbps
    rx: 4.77Kpps 3.44Mbps tx: 4.56Kpps 2.19Mbps
    rx: 4.44Kpps 3.19Mbps tx: 4.68Kpps 2.25Mbps
    rx: 4.28Kpps 3.08Mbps tx: 1.63Kpps 782.39Kbps
    rx: 4.74Kpps 3.41Mbps tx: 0pps 479bps
    rx: 4.29Kpps 3.09Mbps tx: 2.02Kpps 967.67Kbps
    rx: 4.46Kpps 3.21Mbps tx: 4.60Kpps 2.21Mbps
    rx: 4.75Kpps 3.42Mbps tx: 4.43Kpps 2.13Mbps
    rx: 4.09Kpps 2.95Mbps tx: 1.90Kpps 912.48Kbps
    rx: 3.58Kpps 2.58Mbps tx: 0pps 0bps
    rx: 0pps 0bps tx: 11pps 5.76Kbps
    rx: 0pps 0bps tx: 0pps 479bps
    ```


    Test 2

    CONFIG use_tx_ring false
           attack_i % 1024

    rx: 0pps 0bps tx: 0pps 0bps
    rx: 0pps 0bps tx: 0pps 0bps
    rx: 3.07Kpps 2.21Mbps tx: 0pps 0bps
    rx: 4.56Kpps 3.28Mbps tx: 0pps 0bps
    rx: 4.65Kpps 3.35Mbps tx: 0pps 0bps
    rx: 4.09Kpps 2.95Mbps tx: 0pps 0bps
    rx: 4.66Kpps 3.36Mbps tx: 0pps 0bps
    rx: 4.55Kpps 3.28Mbps tx: 0pps 0bps
    rx: 4.13Kpps 2.98Mbps tx: 0pps 0bps
    rx: 4.72Kpps 3.40Mbps tx: 0pps 0bps
    rx: 4.45Kpps 3.21Mbps tx: 0pps 0bps
    rx: 4.23Kpps 3.05Mbps tx: 0pps 0bps
    rx: 4.74Kpps 3.41Mbps tx: 0pps 0bps
    rx: 4.34Kpps 3.12Mbps tx: 0pps 0bps
    rx: 4.30Kpps 3.09Mbps tx: 0pps 0bps
    rx: 4.74Kpps 3.41Mbps tx: 0pps 0bps
    rx: 2.73Kpps 1.97Mbps tx: 0pps 0bps
    rx: 0pps 0bps tx: 0pps 0bps
    rx: 0pps 0bps tx: 0pps 0bps

3. dnshog
