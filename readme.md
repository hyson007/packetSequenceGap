**this app will provide api to decode a range of offset within a packet, using either big endian or little endian to sequence number, then check are those sequence in order or not.**

Example:
ICMP
https://osqa-ask.wireshark.org/questions/3172/icmp-sequence-number-be-vs-le/

Wireshark ICMP has both big endian and little endian format, but the actual ICMP seq in packet are BE at 41-42 byte
(14 Eth + 20 IP + Type (1B) + Code (1B) + CheckSum (2B) + ID (2B))

Test1: 10K sequential ICMP echo request
```
HTTP POST Request:
{
    "Encoding": "BigEndian",
    "StartOffsetZeroIndex": 40,
    "Length": 2,
    "PacketURL": "https://storage.googleapis.com/projectgolive-648ad.appspot.com/10K_icmp_request.pcapng",
    "ReadLocalDownloadedFile": false
}

HTTP Response:
{
    "PacketURL": "https://storage.googleapis.com/projectgolive-648ad.appspot.com/10K_icmp_request.pcapng",
    "PacketLength": 10000,
    "NumberOfGaps": 0,
    "NumberOfOutOfOrder": 0,
    "GapIndex": null,
    "GapMap": {},
    "OutOfOrderSeq": null
}
```

=======================================================================================================
Test2: Intentionally skip certain sequence to simulate the packet lost scenario.

`tshark -r 10K_Normal_icmp_request.pcapng -Y "!(icmp.seq == 937) && !(icmp.seq == 1115) && !(icmp.seq == 2000) && !(icmp.seq == 6654) && !(icmp.seq == 2245) && !(icmp.seq == 5000)"  -w  random_missing_packet.pcap`

```
HTTP POST Request:
{
    "Encoding": "BigEndian",
    "StartOffsetZeroIndex": 40,
    "Length": 2,
    "PacketURL": "https://storage.googleapis.com/projectgolive-648ad.appspot.com/random_missing_packet.pcap",
    "ReadLocalDownloadedFile": false
}

HTTP Response:
{
    "PacketURL": "https://storage.googleapis.com/projectgolive-648ad.appspot.com/random_missing_packet.pcap",
    "PacketLength": 9994,
    "NumberOfGaps": 6,
    "NumberOfOutOfOrder": 0,
    "GapIndex": [
        937,
        1115,
        2000,
        2245,
        5000,
        6654
    ],
    "GapMap": {
        "1115": "seq gap 2",
        "2000": "seq gap 2",
        "2245": "seq gap 2",
        "5000": "seq gap 2",
        "6654": "seq gap 2",
        "937": "seq gap 2"
    },
    "OutOfOrderSeq": null
}
```

=======================================================================================================
Test3: Out of order test, to simulate a bunch of packets arrives late due to possible network congestion.
First to simulate the out of order packets

editcap -r 10K_Normal_icmp_request.pcapng tmp1-1000.pcap 1-1000<br />
editcap -r 10K_Normal_icmp_request.pcapng tmp1001-1100.pcap 1001-1100<br />
editcap -r 10K_Normal_icmp_request.pcapng tmp1101-1200.pcap 1101-1200<br />
editcap -r 10K_Normal_icmp_request.pcapng tmp1201-10000.pcap 1201-10000<br />
mergecap -w outOfOrder.pcap -a tmp1-1000.pcap tmp1101-1200.pcap tmp1001-1100.pcap tmp1201-10000.pcap<br />

```
HTTP POST Request:
{
    "Encoding": "BigEndian",
    "StartOffsetZeroIndex": 40,
    "Length": 2,
    "PacketURL": "https://storage.googleapis.com/projectgolive-648ad.appspot.com/outOfOrder.pcap",
    "ReadLocalDownloadedFile": false
}

HTTP Response:
{
    "PacketURL": "https://storage.googleapis.com/projectgolive-648ad.appspot.com/outOfOrder.pcap",
    "PacketLength": 10000,
    "NumberOfGaps": 3,
    "NumberOfOutOfOrder": 3,
    "GapIndex": [
        1000,
        1200,
        1100
    ],
    "GapMap": {
        "1000": "seq gap 101",
        "1100": "seq gap 101",
        "1200": "seq gap -199"
    },
    "OutOfOrderSeq": [
        1000,
        1200,
        1100
    ]
}
```

=======================================================================================================
Test4: iperf3 udp test
Based on eyeball checking, the sequence number of iperf3 udp packet should be a 4 bytes
from 41-44 bytes (inclusive)

```
HTTP POST Request:
{
    "Encoding": "BigEndian",
    "StartOffsetZeroIndex": 40,
    "Length": 4,
    "PacketURL": "https://storage.googleapis.com/projectgolive-648ad.appspot.com/iperf3_udp2.pcapng",
    "ReadLocalDownloadedFile": false
}

HTTP Response:
{
    "PacketURL": "https://storage.googleapis.com/projectgolive-648ad.appspot.com/iperf3_udp2.pcapng",
    "PacketLength": 267851,
    "NumberOfGaps": 0,
    "NumberOfOutOfOrder": 0,
    "GapIndex": null,
    "GapMap": {},
    "OutOfOrderSeq": null
}
```
The allocated memory looks quite normal even when checking a 400 MB size file.

[GIN] 2022/07/16 - 03:36:08 | 200 |  516.096834ms |       127.0.0.1 | POST     "/config" <br />
Alloc = 8 MiB   TotalAlloc = 999 MiB    Sys = 30 MiB    NumGC = 127 <br />
Alloc = 8 MiB   TotalAlloc = 999 MiB    Sys = 30 MiB    NumGC = 127 <br />
Alloc = 8 MiB   TotalAlloc = 999 MiB    Sys = 30 MiB    NumGC = 127 <br />
Alloc = 8 MiB   TotalAlloc = 999 MiB    Sys = 30 MiB    NumGC = 127 <br />
Alloc = 8 MiB   TotalAlloc = 999 MiB    Sys = 30 MiB    NumGC = 127 <br />
Alloc = 8 MiB   TotalAlloc = 999 MiB    Sys = 30 MiB    NumGC = 127 <br />
Alloc = 8 MiB   TotalAlloc = 999 MiB    Sys = 30 MiB    NumGC = 127 <br />
Alloc = 8 MiB   TotalAlloc = 999 MiB    Sys = 30 MiB    NumGC = 127 <br />
Alloc = 8 MiB   TotalAlloc = 999 MiB    Sys = 30 MiB    NumGC = 127 <br />
Alloc = 8 MiB   TotalAlloc = 999 MiB    Sys = 30 MiB    NumGC = 127 <br />
