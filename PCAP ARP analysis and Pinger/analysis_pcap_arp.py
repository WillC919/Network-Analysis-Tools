import dpkt


def arpAddressStr(bytes, isHex=False):
    answer = ''
    if isHex:
        for intNum in bytes:
            answer += str(hex(intNum))[2:] + '::'
        return answer[0: len(answer) - 2]
    else:
        for intNum in bytes:
            answer += str(intNum) + '.'
        return answer[0: len(answer) - 1]


def analyzeARP(filePath, exchange=1):
    f = open(filePath, 'rb')
    pcap = dpkt.pcap.Reader(f)
    packetType = (2054).to_bytes(2, 'big')
    requestsAndReplies = []
    count = exchange

    for ts, buf in pcap:
        if len(buf) >= 28 and buf[12:14] == packetType:

            hardwareType, protocolType, hardwareSize, protocolSize, opcode \
                = int.from_bytes(buf[14:16], byteorder='big'), (buf[16:18]).hex(), \
                  int.from_bytes(buf[18:19], byteorder='big'), int.from_bytes(buf[19:20], byteorder='big'), \
                  int.from_bytes(buf[20:22], byteorder='big')

            senderMacAddr, senderIPAddr, targetMACAddr, targetIPAddr = buf[22:28], buf[28:32], buf[32:38], buf[38:42]

            if opcode == 1 and senderMacAddr != targetMACAddr:
                requestsAndReplies.append([{'hardwareType': hardwareType, 'protocolType': protocolType,
                                            'hardwareSize': hardwareSize, 'protocolSize': protocolSize,
                                            'senderMacAddr': senderMacAddr, 'senderIPAddr': senderIPAddr,
                                            'targetMACAddr': targetMACAddr, 'targetIPAddr': targetIPAddr,
                                            'opcode': opcode}, None])
            if opcode == 2:
                for requestAndReply in requestsAndReplies:
                    if requestAndReply[0]['targetIPAddr'] == senderIPAddr \
                            and requestAndReply[0]['senderMacAddr'] == targetMACAddr and requestAndReply[1] is None:
                        requestAndReply[1] = {'hardwareType': hardwareType, 'protocolType': protocolType,
                                              'hardwareSize': hardwareSize, 'protocolSize': protocolSize,
                                              'senderMacAddr': senderMacAddr, 'senderIPAddr': senderIPAddr,
                                              'targetMACAddr': targetMACAddr, 'targetIPAddr': targetIPAddr,
                                              'opcode': opcode}
                        count -= 1

            if count == 0:
                for requestAndReply in requestsAndReplies:
                    if requestAndReply[1] is not None:
                        count += 1
                        print(f'====================== ARP Exchange {count} ======================\n\n'
                              f'----------------------- ARP Request ------------------------\n'
                              f'Hardware Type:\t\t\t {requestAndReply[0]["hardwareType"]}\n'
                              f'Protocol Type:\t\t\t 0x{requestAndReply[0]["protocolType"]}\n'
                              f'Hardware Size:\t\t\t {requestAndReply[0]["hardwareSize"]}\n'
                              f'Protocol Size:\t\t\t {requestAndReply[0]["protocolSize"]}\n'
                              f'Opcode:\t\t\t\t {requestAndReply[0]["opcode"]}\n'
                              f'Sender Mac Address:\t\t {arpAddressStr(requestAndReply[0]["senderMacAddr"], True)}\n'
                              f'Sender IP Address:\t\t {arpAddressStr(requestAndReply[0]["senderIPAddr"])}\n'
                              f'Target Mac Address:\t\t {arpAddressStr(requestAndReply[0]["targetMACAddr"], True)}\n'
                              f'Target IP Address:\t\t {arpAddressStr(requestAndReply[0]["targetIPAddr"])}\n'
                              f'\n\n'
                              f'----------------------- ARP Response -----------------------\n'
                              f'Hardware Type:\t\t\t {requestAndReply[1]["hardwareType"]}\n'
                              f'Protocol Type:\t\t\t 0x{requestAndReply[1]["protocolType"]}\n'
                              f'Hardware Size:\t\t\t {requestAndReply[1]["hardwareSize"]}\n'
                              f'Protocol Size:\t\t\t {requestAndReply[1]["protocolSize"]}\n'
                              f'Opcode:\t\t\t\t {requestAndReply[1]["opcode"]}\n'
                              f'Sender Mac Address:\t\t {arpAddressStr(requestAndReply[1]["senderMacAddr"], True)}\n'
                              f'Sender IP Address:\t\t {arpAddressStr(requestAndReply[1]["senderIPAddr"])}\n'
                              f'Target Mac Address:\t\t {arpAddressStr(requestAndReply[1]["targetMACAddr"], True)}\n'
                              f'Target IP Address:\t\t {arpAddressStr(requestAndReply[1]["targetIPAddr"])}\n\n'
                              )
                    if count == exchange:
                        return

    print('No Complete ARP Packets Exchange to analyze')


if __name__ == '__main__':
    fileName = input('Enter filename: ')
    analyzeARP(fileName)

