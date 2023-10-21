import time
import dns.resolver


def mydig(url):
    root = '192.58.128.30'
    target = url
    origin = target
    server = root
    print(f'QUESTION SECTION: \n{url}. IN A\n')

    try:  # Single Iterative process of searching through the DNS
        iterations = 0
        when = time.ctime()
        start_time = time.time()
        while True:
            msg = dns.message.make_query(url, 'A')
            result = dns.query.udp(msg, server)
            iterations += 1

            if not result.answer and not result.authority and not result.additional:
                result = dns.query.tcp(msg, server)
            if str(result.rcode()) != '0':
                result = dns.query.udp(msg, root)
            if str(result.rcode()) != '0' or iterations > 300:
                raise Exception

            if not result.answer:
                if result.additional:
                    for index in result.additional:
                        info = index.to_text().split()
                        if info[3] == 'A':
                            server = info[4]
                            break
                else:
                    url = str(result.authority[0][0])
            elif result.answer[0].to_text().find('IN CNAME ') != -1:
                url = str(result.answer[0][0])
                target = url
                server = root
            else:
                if target != url:
                    server = str(result.answer[0][0])
                    url = target
                else:
                    end_time = time.time()
                    print(f"ANSWER SECTION:\n{result.answer[0].to_text().replace((url+'.'), origin).replace(url, (origin+'.'))}\n")
                    print(f'Query time: {int((end_time - start_time) * 1000)} ms')
                    print(f'WHEN: {when}\n\n')
                    break
    except Exception:
        print(f'ERROR! UNABLE TO FETCH IP OF \"{origin}\"!!!')


if __name__ == '__main__':
    name = input('Enter Domain: ')
    mydig(name)
