import os
import time
import threading
import dns.message
import dns.name
import dns.query
from subprocess import Popen, PIPE, signal, call
import json
import csv
import ssl


def query_DoT(qname):
    qname = dns.name.from_text(qname)
    q = dns.message.make_query(qname, dns.rdatatype.A)
    dns.query.tls(q, '8.8.8.8')

def query_DoT2(qname, rdatatype):
    '''
        rdatatype values = (dns.rdatatype.A, dns.rdatatype.PTR, dns.rdatatype.AAAA, dns.rdatatype.)
    '''
   
    qname = dns.name.from_text(qname)
    q = dns.message.make_query(qname, rdatatype)
    dns.query.tls(q, '8.8.8.8')    

def query_DoT3(qname, rdatatype):
    '''
        rdatatype values = (dns.rdatatype.A, dns.rdatatype.PTR, dns.rdatatype.AAAA, dns.rdatatype.)
    '''
    while True:
        try:
            os.environ["SSLKEYLOGFILE"] = "/home/ubuntu/sslkeylog.log"
            context = ssl.create_default_context()
            context.keylog_filename
 
            qname = dns.name.from_text(qname)
            q = dns.message.make_query(qname, rdatatype)
            r = dns.query.tls(q, '8.8.8.8', ssl_context=context, server_hostname='8.8.8.8')   
            break
        except Exception as e:
            print(e)
            time.sleep(5)
            continue
        
    
def query_DoT_kdig(qname):
    # os.system("export SSLKEYLOGFILE=$HOME/sslkeylog.log")
    os.system("export SSLKEYLOGFILE=/home/research/sslkeylog.log && kdig -d @8.8.8.8 +tls-ca +tls-host=dns.google.com " + qname )

def query_DoT_kdig2(qname, rdatatype):
    '''
        rdatatype values = (A, PTR, AAAA, MX)
    '''

    os.system("export SSLKEYLOGFILE=/home/research/sslkeylog.log && kdig -t " + rdatatype + " -d @8.8.8.8 +tls-ca +tls-host=dns.google.com " + qname )    

# query_DoT("example.com")

# def start_capturing(pid):
#     os.system("sudo strace -p " + str(pid) + " -f -e trace=network -o tes.pcap -s 10000")

process = None
def tcpdump_thread(intf, domainpcap):
    
    process_ = Popen(['echo', 'password'], stdout=PIPE)

    process = Popen(['sudo', '-S', '/usr/sbin/tcpdump', '-i', intf, 'tcp', 'port', '853', '-w', domainpcap], stdin=process_.stdout)


def get_domain(domain, outputdir):
    domainpcap = outputdir + "/" + domain + ".pcap"
    print(domainpcap)
    if not os.path.exists(domainpcap):
        process = Popen(['tcpdump', '-i', 'eth0', 'tcp', 'port', '853', '-w', domainpcap])
        time.sleep(2)
        query_DoT_kdig(domain)
        time.sleep(5)
        process.send_signal(signal.SIGINT)
        
        return domainpcap
    # return -1


def domains_dga(directory, output_dir, tool):
    for subdir, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith("_DGArchive.json"):

                abs_path = os.path.join(subdir, file)
                with open (abs_path) as fj:
                    try:
                        data = json.load(fj)
                        for entry in data['hits']:
                            domain = entry['domain']
                            domainpcap = output_dir + domain + ".pcap"

                            print("\t", domain)

                            if os.path.exists(domainpcap):
                                continue

                            process = Popen(['tcpdump', '-i', 'eth0', 'tcp', 'port', '853', '-w', domainpcap])

                            time.sleep(2)

                            if tool == "dnspy":
                                query_DoT(domain)
                            elif tool == "kdig":
                                query_DoT_kdig(domain)
                            else:
                                exit("Incorrect DNS tool name")

                            time.sleep(3)

                            process.send_signal(signal.SIGINT)
                            
                    except Exception as e:
                        print("Error is ", e)

def domains_top1m(topm1m_csv, output_dir, tool):

    with open(topm1m_csv, newline='') as csvfile:
        reader = csv.reader(csvfile, delimiter=',')
        for row in reader:
            domain = row[1]
            domainpcap = output_dir + domain + ".pcap"

            print("\t", domain)

            if os.path.exists(domainpcap):
                continue

            process = Popen(['tcpdump', '-i', 'eth0', 'tcp', 'port', '853', '-w', domainpcap])

            time.sleep(2)

            if tool == "dnspy":
                query_DoT(domain)
            elif tool == "kdig":
                query_DoT_kdig(domain)
            else:
                exit("Incorrect DNS tool name")

            time.sleep(5)

            process.send_signal(signal.SIGINT)
                            

def domains_ctu(output_dir, tool):
    domains_info = {}
    domains_info_fname = output_dir + "domains_info.csv"
    if os.path.exists(domains_info_fname):
        with open(domains_info_fname) as csvfile:
            reader = csv.reader(csvfile, delimiter=',')
            for row in reader:
                domain = row[0]
                query_type = row[1]
                rcode = row[2]
                domains_info[domain] = [query_type, rcode]          
            csvfile.close()
    
    '''
    for subdir, dirs, files in os.walk("CTU_dnspython_old"):
        for file in files:
            if file not in domains_info:
                domains_info[file] = []
    '''
             

    csvfile_a = open(domains_info_fname, 'a+', newline='')
    writer = csv.writer(csvfile_a, delimiter=',')

    dirs = "../CTU/CTU-Malware-Capture-Botnet-" 
    all_dirs = []
    for i in range(42, 55):
        all_dirs.append(dirs + str(i))

    for dirr in all_dirs:
        dnslog_name = dirr + '/' + 'dns.log'
        print(dnslog_name)
        with open(dnslog_name) as f_dns:
            i = 0
            ips_parsed = set()
            for l in f_dns:
                if l[0] != "#":
                    i += 1
                    l = l.split('	')
                    src_ip = l[2]
                    dst_ip = l[4]

                    try:
                        domain = l[8]
                        qtype = l[11] # A == 1        
                        rcode = l[13] # NXD == 3, NOERROR == 3
                        
                        if qtype == "1":
                            qtype = "A"
                        elif qtype == "2":
                            qtype = "NS"
                        elif qtype == "12":
                            qtype = "PTR"
                        elif qtype == "15":
                            qtype = "MX"
                        elif qtype == "28":
                            qtype = "AAAA"
                        elif qtype == "33":
                            qtype = "SRV"
                        else:
                            # exit("Diff qtype " + qtype)
                            print("Diff qtype " + qtype)
                            continue
	
		       	
                        if qtype == "A" and os.path.exists("CTU_dnspython_old/" + domain + ".pcap"):
                            # print("HERE")
                            os.system("mv 'CTU_dnspython_old/" + domain + ".pcap' '" + output_dir + domain + ".A.pcap'")
                            domains_info[domain] = [qtype, rcode]
                            writer.writerow([domain, qtype, rcode])
                        	
                        elif domain not in domains_info:
                            # continue
                            domainpcap = output_dir + domain + "." + qtype + ".pcap"

                            print("\t", domainpcap)
                            
                            process = Popen(['tcpdump', '-i', 'eth0', 'tcp', 'port', '853', '-w', domainpcap])

                            time.sleep(1.5)

                            if tool == "dnspy":
                                query_DoT2(domain, qtype)
                            elif tool == "kdig":
                                query_DoT_kdig2(domain, qtype)
                            else:
                                exit("Incorrect DNS tool name")

                            time.sleep(2.5)

                            process.send_signal(signal.SIGINT)

                            domains_info[domain] = [qtype, rcode]

                            writer.writerow([domain, qtype, rcode])

                    except Exception as e:
                        print(e)
                        exit()
                        continue


def domains_ctu_fast(output_dir, tool):

    limit = 70000
    existing_domains = {}
    csvfile = open("existing_domains.csv", newline='')
    reader = csv.reader(csvfile, delimiter=',')
    
    for row in reader:
        existing_domains[row[0]] = [row[1], row[2]]
        
    

    dirs = "./CTU/CTU-Malware-Capture-Botnet-" 
    all_dirs = []
    for i in range(42, 55):
        all_dirs.append(dirs + str(i))

    for i in range(1, 100):
        output_pcap = output_dir + "all_domains" + str(i) + ".pcap"
        output_domains = output_dir + "all_domains" + str(i) + ".txt"
        if not (os.path.exists(output_pcap) and os.path.exists(output_domains)):
            break
        elif os.path.exists(output_domains):
            frr = open(output_domains, newline='')
            reader = csv.reader(frr, delimiter=',')
            for row in reader:
                existing_domains[row[0] + "." + row[1] + ".pcap"] = [row[0], row[1]]
            frr.close()
                
    print(len(existing_domains))    
    print("Done checking ...")

    csvfile_w = open(output_domains, 'w', newline='')
    writer = csv.writer(csvfile_w, delimiter=',')

    process = Popen(['tcpdump', '-i', 'eth0', 'tcp', 'port', '853', '-w', output_pcap])
    
    time.sleep(1)
    
    c = 0
    remaining_domains = set()
    for dirr in all_dirs:
        if c == limit:
            break
        dnslog_name = dirr + '/' + 'dns.log'
        print(dnslog_name)
        with open(dnslog_name) as f_dns:
            i = 0
            for l in f_dns:
                if l[0] != "#":
                    i += 1
                    l = l.split('	')

                    try:
                        domain = l[8]
                        qtype = l[11] # A == 1        
                        rcode = l[13] # NXD == 3, NOERROR == 3
                        
                        if qtype == "1":
                            qtype = "A"
                        elif qtype == "2":
                            qtype = "NS"
                        elif qtype == "12":
                            qtype = "PTR"
                        elif qtype == "15":
                            qtype = "MX"
                        elif qtype == "16":
                            qtype = "MX"
                        elif qtype == "28":
                            qtype = "AAAA"
                        elif qtype == "33":
                            qtype = "SRV"
                        elif qtype == "6":
                            qtype = "SOA"
                        else:
                            # exit("Diff qtype " + qtype)
                            # print("Diff qtype " + qtype)
                            continue
	
                        domain_file = domain + '.' + qtype + '.pcap'
                        if not domain_file in existing_domains:
                            # remaining_domains.add(domain_file)
                            # continue
                            
                            print(domain_file)
                            if tool == "dnspy":
                                query_DoT3(domain, qtype)
                            elif tool == "kdig":
                                query_DoT_kdig2(domain, qtype)
                            else:
                                exit("Incorrect DNS tool name")

                            writer.writerow([domain, qtype])
                            existing_domains[domain_file] = [domain, qtype]

                            time.sleep(0.5)

                            c += 1
                            if c == limit:
                                break
                    

                    except Exception as e:
                        print(e)
                        exit()

            print(len(remaining_domains))
    print(len(remaining_domains))
    print("Done capturing")
    time.sleep(10)
    process.send_signal(signal.SIGINT)


    
    
def trans_dga_all_qtypes(output_dir, tool):
    domains_info = {}
    domains_info_fname =  output_dir + "domains_info.csv"
    if os.path.exists(domains_info_fname):
        with open(domains_info_fname) as csvfile:
            reader = csv.reader(csvfile, delimiter=',')
            for row in reader:
                domain = row[0]
                query_type = row[1]
                # rcode = row[2]
                domains_info[domain] = [query_type]          
            csvfile.close()

    csvfile_a = open(domains_info_fname, 'a+', newline='')
    writer = csv.writer(csvfile_a, delimiter=',')

    with open("trans_dga_dns_info.csv", newline='') as csvfile:
        reader = csv.reader(csvfile, delimiter=',')
        i = 0
        for row in reader:
            i += 1
            pcap_fname = row[0]
            for e in row[1:]:
                e = e.split(" ")
                domain = e[0]
                rdatatype = e[1]
                qclass = e[2] 

                if rdatatype == "1":
                    if tool == "dnspy":
                        if os.path.exists("dga_dot/" + domain + ".pcap") or os.path.exists("top1m_dot/" + domain + ".pcap") or os.path.exists("CTU_dot/" + domain + ".pcap"):
                            print("Domain " + domain + " exists")
                            continue
                    elif tool == "kdig":
                        if os.path.exists("dga_dot_kdig/" + domain + ".pcap") or os.path.exists("top1m_dot_kdig/" + domain + ".pcap") or os.path.exists("CTU_dot_kdig/" + domain + ".pcap"):
                            print("Domain " + domain + " exists")
                            continue

                if domain not in domains_info:

                    if rdatatype == "1":
                        qtype = "A"
                    elif rdatatype == "2":
                        qtype = "NS"
                    elif rdatatype == "12":
                        qtype = "PTR"
                    elif rdatatype == "15":
                        qtype = "MX"
                    elif rdatatype == "28":
                        qtype = "AAAA"
                    else:
                        exit("Diff qtype " + rdatatype)
                        continue

                    print(i, pcap_fname, domain, qtype)
                    domainpcap = output_dir + domain + "." + qtype + ".pcap"
                    process = Popen(['tcpdump', '-i', 'eth0', 'tcp', 'port', '853', '-w', domainpcap])
                    time.sleep(2)

                    if tool == "dnspy":
                        query_DoT2(domain, qtype)
                    elif tool == "kdig":
                        query_DoT_kdig2(domain, qtype)
                    else:
                        exit("Incorrect DNS tool name")

                    time.sleep(5)
                    process.send_signal(signal.SIGINT)
                    domains_info[domain] = [qtype]
                    writer.writerow([domain, qtype])

            #         break
            # break
          

def __main__():
    # domains_dga("dfrws_info_nxds", "dga_dot_kdig/", "kdig")
    # domains_dga("cuckoomalpedia_info_nxds", "dga_dot_kdig/", "kdig")
    # domains_dga("malpedia_info_nxds", "dga_dot_kdig/", "kdig")
    # domains_dga("VS003_info_nxds", "dga_dot_kdig/", "kdig")
    # domains_top1m("top-1m.csv", "top1m_dot_kdig/", "kdig")
    # get_domain("aewuiw.com", "DoT_sslkey")

    # domains_ctu("CTU_dnspython_ds/", "dnspy")
    
    # query_DoT3("facebook.com", 'A')
    domains_ctu_fast("CTU_dnspython_ds3/", "dnspy") 
    pass

    # trans_dga_all_qtypes("dga_dnspy_qtypes/", "dnspy")
    
    # trans_dga_all_qtypes("CTU_kdig_ds/", "kdig")
    
    '''
    fw = open("DGA_dnspython_ds2/domains_info.csv", 'w', newline='')
    writer = csv.writer(fw, delimiter=',')
    for subdir, dirs, files in os.walk("DGA_dnspython_ds2"):
        for file in files:
        	if file.endswith(".pcap"):
        		abs_path = os.path.join(subdir, file)
        		new_file = abs_path[:-5]
        		new_file = new_file + ".A.pcap" 
        		os.system("mv " + abs_path + " " + new_file)
        		writer.writerow([new_file, "A"])
    '''

if __name__ == "__main__":

    __main__()
