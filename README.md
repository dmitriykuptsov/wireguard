# wireguard
Prototype implementation of WireGuard protocol  

WireGuard is a recent development of a novel VPN protocol that requires
    1-RTT to establish a secure, authenticated channel between peers. 
    WireGuard revolves around the idea of crypto routing - routing based on 
    the public keys of the peers. WireGuard uses EC curve X25519 for 
    identification and authentication, and a set of novel algorithms to secure 
    data plane traffic - ChaCha20 and Blake2s algorithms. In this document, we 
    present a simple implementation of WireGuard protocol in userspace using 
    Python language. Our implementation, although is a proof-of-concept, 
    achieves 70Mb/s throughput which is sufficient for single-user deployments.