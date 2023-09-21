from scapy.all import *


def dns_query(dns_name):
    dns_result = sr1(IP(dst="114.114.114.114") / UDP() / DNS(rd=1, qd=DNSQR(qname=dns_name)))
    # id标识字段（匹配请求与回应），qr等于0标识查询报文，opcode为0表示标准查询，rd为1表示期望递归，qname参数为要查询的域名
    layer = 1
    while True:  # 不太确定DNSRR到底有几组
        try:
            if dns_result.getlayer(DNS).fields['an'][layer].fields['type'] == 1:
                dns_result_ip = dns_result.getlayer(DNS).fields['an'][layer].fields['rdata']
                # 每一层就是一个记录，但是不一定是A，可能是CNAME
                print('域名: {0:<18} 对应的IP地址：{1}'.format(dns_name, dns_result_ip))
            layer += 1
        except:  # 如果超出范围就跳出循环
            break


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    dns_query(sys.argv[1])

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
