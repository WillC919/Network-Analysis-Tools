import dpkt


def find(mappings, attribute, name):
    for mapping in mappings:
        if mapping[attribute] == name:
            return mapping
    return None


def getValue(mappings, key):
    try:
        return mappings[key]
    except KeyError or NameError:
        return None


def ipConvert(byt):
    ip = ""
    for ipB in byt:
        ip += str(ipB) + "."
    return ip[0: len(ip) - 1]


def printPackets(pcap, transactions, windows):
    flowMap, ackToTsMap = {}, {}
    sdIP, rvIP = None, None

    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data

        if ip.data.flags & 18 == 2:
            if sdIP is None and rvIP is None:
                sdIP = ip.src
                rvIP = ip.dst

            flowMap.update({ip.data.sport: {
                    "rvPort": ip.data.dport, "sdSend": [], "rvSend": [],
                    "totalBytes": 0, "startTime": ts, "endTime": ts,
                    "rtt": ts, "cwnd": [], "cwndMsre": {"packets": 0, "time": -1},
                    "retransmission": {"timeOut": 0, "triAck": 0, "other": 0, "ackNum": -1, "ackTS": -1,
                                       "dupCount": 0}}})
        elif ip.data.flags & 18 == 18:
            flow = getValue(flowMap, ip.data.dport)
            flow["rtt"] = ts - flow["rtt"]
        elif ip.data.flags & 16 == 16:
            flow = getValue(flowMap, ip.data.sport)

            if flow is not None:
                flow["totalBytes"] += ip.len
                flow["endTime"] = ts
                flow["cwndMsre"]["packets"] += 1

                if flow["cwndMsre"]["time"] == -1:
                    flow["cwndMsre"]["time"] = ts

                if len(flow["sdSend"]) < transactions:
                    if find(flow["sdSend"], "seqNum", ip.data.seq) is None or \
                            find(flow["sdSend"], "ackNum", ip.data.ack) is None:
                        flow["sdSend"].append({"seqNum": ip.data.seq, "ackNum": ip.data.ack, "window": ip.data.win})

                if flow["retransmission"]["ackNum"] == ip.data.seq:
                    if ts - flow["retransmission"]["ackTS"] > 2 * flow["rtt"]:
                        flow["retransmission"]["timeOut"] += 1
                    elif flow["retransmission"]["dupCount"] >= 2:
                        flow["retransmission"]["triAck"] += 1
                else:
                    newDict = {str(ip.data.seq): ts}
                    ackToTsMap.update(newDict)

            else:
                flow = getValue(flowMap, ip.data.dport)

                if flow is not None:
                    if len(flow["rvSend"]) < transactions:
                        flow["rvSend"].append({"seqNum": ip.data.seq, "ackNum": ip.data.ack, "window": ip.data.win})

                    if ts - flow["cwndMsre"]["time"] > flow["rtt"] - 0.125 * flow["rtt"]:
                        if len(flow["cwnd"]) < windows:
                            flow["cwnd"].append(flow["cwndMsre"]["packets"])
                            flow["cwndMsre"] = {"packets": 0, "time": -1}

                    if flow["retransmission"]["ackNum"] == ip.data.ack:
                        if flow["retransmission"]["dupCount"] < 3:
                            flow["retransmission"]["dupCount"] += 1
                    else:
                        flow["retransmission"]["ackNum"] = ip.data.ack
                        try:
                            flow["retransmission"]["ackTS"] = ackToTsMap[str(ip.data.ack)]
                            del ackToTsMap[str(ip.data.ack)]
                        except KeyError:
                            flow["retransmission"]["ackTS"] = ts
                        flow["retransmission"]["dupCount"] = 0

    counter = 1
    for sdPort in flowMap:
        print(f'Flows {counter}:')
        print(f'Source Port: {sdPort}, Source IP Address {ipConvert(sdIP)}')
        print(f'Destination Port: {flowMap[sdPort]["rvPort"]}, Destination IP Address {ipConvert(rvIP)}')
        print(f'Total Throughput: {round(flowMap[sdPort]["totalBytes"]/(flowMap[sdPort]["endTime"]-flowMap[sdPort]["startTime"]), 2)} bytes/secs')
        counter += 1

        for index in range(transactions):
            print(f'\n\tTransaction {index + 1}:')
            print(f'\tSender -> Seq Number: {flowMap[sdPort]["sdSend"][index]["seqNum"]}, '
                  f'Ack Number: {flowMap[sdPort]["sdSend"][index]["ackNum"]}, '
                  f'Receive Window Size: {flowMap[sdPort]["sdSend"][index]["window"]}')
            print(f'\tReceiver -> Seq Number: {flowMap[sdPort]["rvSend"][index]["seqNum"]}, '
                  f'Ack Number: {flowMap[sdPort]["rvSend"][index]["ackNum"]}, '
                  f'Receive Window Size: {flowMap[sdPort]["rvSend"][index]["window"]}')

        print()
        cwIndex = 0
        for cw in flowMap[sdPort]["cwnd"]:
            cwIndex += 1
            print(f"\tCongestion Window {cwIndex}: {cw} packets")

        print(f'\n\tTriple Ack Retransmission: {flowMap[sdPort]["retransmission"]["triAck"]}')
        print(f'\tTimeout Retransmission: {flowMap[sdPort]["retransmission"]["timeOut"]}')
        print(f'\tOther Retransmission: {flowMap[sdPort]["retransmission"]["other"]}')
        print('\n')


def analyzeTCP(filename):
    f = open(filename, 'rb')
    pcap = dpkt.pcap.Reader(f)
    printPackets(pcap, 2, 3)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    fileName = input('Enter filename: ')
    analyzeTCP(fileName)

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
