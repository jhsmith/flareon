# FlareOn 2018 Challenge 11 solution

You must first run tcpflow on the provided pcap to reconstruct TCP streams.
Then run the tool passing in the path to the pcap and the flow directory:

```
$ python solution.py ./pcap.pcap ./flows/
```


## Requirements
Install via pip the following packages:
* hexdump
* scapy
* M2Crypto
* pycrypto

Install vivisect, either:
* Clone https://github.com/vivisect/vivisect and place that in your PYTHONPATH
* Install via pip:
```
$ pip install https://github.com/williballenthin/vivisect/zipball/master
```


