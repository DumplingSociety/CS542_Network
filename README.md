# CS542_Network

## Project: A raw socket ping tool by python

### Preparation

* Turn off the kernel icmp reply 
    echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all

* Env requirement: Linux, Python3
### Command to run: 
    sudo ./reciver_sender.py ( receiver run first )
    sudo ./sender.py 127.0.0.1 


### Result:
After running both python, we will have 2 text files generated.
1. receiver_icmp.txt is from receiver 
1. sender_icmp.txt from sender
