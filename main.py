import json
import os
import random
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rdatatype
import dns.rcode

ROOT_SERVERS = [
    "198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13",
    "192.203.230.10", "192.5.5.241", "192.112.36.4", "198.97.190.53",
    "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",
    "202.12.27.33",
]
DOMAIN_RE = re.compile(r"^(?=.{1,253}\.?$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.?$")


def query_dns_server(server_ip, domain, record_type="A", timeout=3):
    query = dns.message.make_query(domain, record_type)
    query.flags &= ~dns.flags.RD
    start = time.perf_counter()
    response = dns.query.udp(query, server_ip, timeout=timeout)
    if response.flags & dns.flags.TC:
        response = dns.query.tcp(query, server_ip, timeout=timeout)
    return response, (time.perf_counter() - start) * 1000


def rrsets_to_data(rrsets):
    return [
        {"name": rrset.name.to_text(), "type": dns.rdatatype.to_text(rrset.rdtype),
         "ttl": rrset.ttl, "values": [item.to_text() for item in rrset]}
        for rrset in rrsets
    ]


def get_glue_ips(response):
    return [item.to_text() for rrset in response.additional
            if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA) for item in rrset]


def get_nameservers(response):
    return [item.target.to_text() for rrset in response.authority
            if rrset.rdtype == dns.rdatatype.NS for item in rrset]


def resolve_nameserver_ip(ns_name):
    import dns.resolver
    try:
        return dns.resolver.resolve(ns_name, "A", lifetime=3)[0].to_text()
    except Exception:
        return None


def server_role(step, answer):
    if step == 1:
        return "Root nameserver"
    if answer:
        return "Authoritative nameserver"
    return "Delegated nameserver"


def trace_dns(domain, record_type="A", max_steps=12):
    domain = domain.strip().lower().rstrip(".")
    record_type = record_type.upper()
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError("Enter a valid domain name, such as example.com.")
    if record_type not in {"A", "AAAA", "MX", "NS", "TXT"}:
        raise ValueError("Unsupported record type.")

    current_servers = ROOT_SERVERS.copy()
    steps, errors = [], []
    started = time.perf_counter()

    for step_number in range(1, max_steps + 1):
        random.shuffle(current_servers)
        response = server_used = elapsed = None
        for server_ip in current_servers[:8]:
            try:
                response, elapsed = query_dns_server(server_ip, domain, record_type)
                server_used = server_ip
                break
            except Exception as error:
                errors.append(f"{server_ip}: {type(error).__name__}")
        if response is None:
            raise RuntimeError("No nameserver responded. Check this machine's network access.")

        answer = rrsets_to_data(response.answer)
        authority = rrsets_to_data(response.authority)
        additional = rrsets_to_data(response.additional)
        glue_ips = get_glue_ips(response)
        nameservers = get_nameservers(response)
        steps.append({
            "number": step_number, "server": server_used,
            "role": server_role(step_number, answer), "duration_ms": round(elapsed, 1),
            "status": dns.rcode.to_text(response.rcode()), "answer": answer,
            "authority": authority, "additional": additional,
            "next_servers": glue_ips, "nameservers": nameservers,
        })
        if answer or response.rcode() != dns.rcode.NOERROR:
            break
        if glue_ips:
            current_servers = glue_ips
            continue
        resolved_ips = [ip for name in nameservers if (ip := resolve_nameserver_ip(name))]
        if not resolved_ips:
            break
        steps[-1]["next_servers"] = resolved_ips
        current_servers = resolved_ips

    return {
        "domain": domain, "record_type": record_type, "steps": steps,
        "total_ms": round((time.perf_counter() - started) * 1000, 1),
        "complete": bool(steps and (steps[-1]["answer"] or steps[-1]["status"] != "NOERROR")),
        "attempt_errors": len(errors),
    }


HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DNS Field Guide — Trace a lookup</title>
<style>
:root{--ink:#101820;--paper:#f4f7f8;--white:#fff;--blue:#155eef;--cyan:#8ee3ef;--line:#aebbc5;--muted:#536471;--red:#d92d20;--yellow:#ffd84d}*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font-family:Arial,Helvetica,sans-serif}.topbar{height:12px;background:var(--blue);border-bottom:3px solid var(--ink)}header{display:grid;grid-template-columns:1fr auto;gap:24px;padding:30px 5vw 26px;border-bottom:2px solid var(--ink);background:var(--white)}.brand{font:900 clamp(30px,5vw,68px)/.88 Arial,sans-serif;letter-spacing:-.065em;text-transform:uppercase}.brand span{color:var(--blue)}.header-note{max-width:310px;align-self:end;font:700 13px/1.45 'Courier New',monospace;text-transform:uppercase}.workspace{display:grid;grid-template-columns:minmax(300px,420px) 1fr;min-height:calc(100vh - 170px)}aside{padding:34px 32px 60px 5vw;border-right:2px solid var(--ink);background:var(--white)}.eyebrow,.label{font:700 11px/1.2 'Courier New',monospace;letter-spacing:.12em;text-transform:uppercase}.intro{font-size:18px;line-height:1.45;margin:14px 0 34px}.field{margin-bottom:20px}label{display:block;margin-bottom:8px}input,select,button{border:2px solid var(--ink);border-radius:0;background:var(--white);color:var(--ink);font:700 16px Arial,sans-serif;height:52px}input{width:100%;padding:0 14px}select{width:100%;padding:0 12px}button{width:100%;background:var(--blue);color:white;cursor:pointer;text-transform:uppercase;letter-spacing:.04em}button:hover{background:var(--ink)}button:focus,input:focus,select:focus{outline:4px solid var(--yellow);outline-offset:2px}button:disabled{background:var(--muted);cursor:wait}.lesson{margin-top:34px;border-top:2px solid var(--ink);padding-top:18px}.lesson ol{padding-left:22px;line-height:1.55;font-size:14px}.status{min-height:42px;margin-top:16px;font:700 13px/1.5 'Courier New',monospace}.status.error{color:var(--red)}main{padding:34px 5vw 70px;overflow:hidden}.empty{max-width:640px;margin:10vh auto;border:2px solid var(--ink);background:var(--white);padding:32px}.empty-mark{font:900 70px/1 Arial;color:var(--blue)}.empty h2{font-size:28px;margin:12px 0}.empty p{color:var(--muted);line-height:1.55}.results{display:none}.summary{display:grid;grid-template-columns:1fr auto auto;gap:20px;align-items:end;border-bottom:2px solid var(--ink);padding-bottom:20px;margin-bottom:32px}.summary h1{font-size:clamp(28px,4vw,52px);letter-spacing:-.045em;margin:5px 0 0;word-break:break-all}.metric{border-left:2px solid var(--ink);padding-left:18px}.metric b{display:block;font-size:25px}.route{position:relative}.hop{display:grid;grid-template-columns:56px minmax(180px,260px) 1fr;position:relative;min-height:150px;opacity:0;transform:translateY(8px);animation:arrive .3s forwards}.hop:before{content:"";position:absolute;left:27px;top:52px;bottom:-2px;border-left:3px solid var(--blue)}.hop:last-child:before{display:none}.node{width:56px;height:56px;border:3px solid var(--ink);background:var(--yellow);display:grid;place-items:center;font:900 18px 'Courier New',monospace;z-index:1}.hop-card{border:2px solid var(--ink);background:var(--white);padding:16px;margin:0 18px 28px}.hop-card h3{margin:3px 0 9px;font-size:17px}.server{font:700 13px 'Courier New',monospace;color:var(--blue)}.latency{display:inline-block;background:var(--cyan);border:1px solid var(--ink);padding:4px 6px;margin-top:12px;font:700 11px 'Courier New',monospace}.packet{border-top:2px solid var(--ink);padding:13px 0 25px;min-width:0}.packet-row{display:grid;grid-template-columns:90px 1fr;gap:10px;margin-bottom:10px;font:13px/1.45 'Courier New',monospace}.packet-row b{text-transform:uppercase;font-size:10px;letter-spacing:.08em}.values{word-break:break-word}.final{background:var(--blue);color:white;padding:16px;border:2px solid var(--ink);font:700 14px/1.5 'Courier New',monospace}@keyframes arrive{to{opacity:1;transform:none}}@media(max-width:850px){header{grid-template-columns:1fr}.workspace{grid-template-columns:1fr}aside{border-right:0;border-bottom:2px solid var(--ink);padding-right:5vw}.summary{grid-template-columns:1fr 1fr}.summary h1{grid-column:1/-1}.hop{grid-template-columns:44px 1fr}.node{width:44px;height:44px}.hop:before{left:21px;top:42px}.packet{grid-column:2;margin:0 18px 16px}.hop-card{margin-bottom:8px}}@media(prefers-reduced-motion:reduce){.hop{animation:none;opacity:1;transform:none}}
</style></head><body><div class="topbar"></div><header><div class="brand">DNS <span>Field Guide</span></div><div class="header-note">An interactive map of the resolver's path from the root to your answer.</div></header><div class="workspace"><aside><div class="eyebrow">Start a trace</div><p class="intro">Enter a domain. We will ask each nameserver directly, the same way a recursive resolver finds an answer.</p><form id="form"><div class="field"><label class="label" for="domain">Domain name</label><input id="domain" name="domain" value="example.com" placeholder="example.com" required autocomplete="off" spellcheck="false"></div><div class="field"><label class="label" for="type">Record type</label><select id="type" name="type"><option>A — IPv4 address</option><option>AAAA — IPv6 address</option><option>MX — Mail server</option><option>NS — Nameserver</option><option>TXT — Text record</option></select></div><button id="go">Trace this domain</button><div id="status" class="status" role="status"></div></form><div class="lesson"><div class="eyebrow">What to watch</div><ol><li>The root points toward the top-level domain.</li><li>The TLD points toward the domain's nameserver.</li><li>The authoritative server returns the record.</li></ol></div></aside><main><section id="empty" class="empty"><div class="empty-mark">→</div><h2>The route appears here.</h2><p>Each box is one direct DNS question. The connecting line shows how referrals lead the resolver closer to the server that owns the answer.</p></section><section id="results" class="results"><div class="summary"><div><div class="eyebrow">Completed trace</div><h1 id="title"></h1></div><div class="metric"><span class="label">Hops</span><b id="hopCount"></b></div><div class="metric"><span class="label">Total</span><b id="total"></b></div></div><div id="route" class="route"></div></section></main></div>
<script>
const form=document.querySelector('#form'),go=document.querySelector('#go'),statusEl=document.querySelector('#status');
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function rows(label,sets){if(!sets.length)return '';return `<div class="packet-row"><b>${label}</b><div class="values">${sets.map(x=>`${esc(x.name)} <strong>${esc(x.type)}</strong> ${x.values.map(esc).join(' · ')}`).join('<br>')}</div></div>`}
function render(data){document.querySelector('#empty').style.display='none';document.querySelector('#results').style.display='block';document.querySelector('#title').textContent=`${data.domain} / ${data.record_type}`;document.querySelector('#hopCount').textContent=data.steps.length;document.querySelector('#total').textContent=`${data.total_ms} ms`;document.querySelector('#route').innerHTML=data.steps.map((s,i)=>`<article class="hop" style="animation-delay:${i*140}ms"><div class="node">${String(s.number).padStart(2,'0')}</div><div class="hop-card"><div class="label">${esc(s.role)}</div><h3>${esc(s.server)}</h3><div class="server">Response: ${esc(s.status)}</div><span class="latency">${s.duration_ms} ms</span></div><div class="packet">${rows('Answer',s.answer)}${rows('Referral',s.authority)}${rows('Glue',s.additional)}${s.answer.length?`<div class="final">Answer found → ${s.answer.flatMap(x=>x.values).map(esc).join(' · ')}</div>`:''}</div></article>`).join('')}
form.addEventListener('submit',async e=>{e.preventDefault();go.disabled=true;go.textContent='Tracing…';statusEl.className='status';statusEl.textContent='Querying the DNS hierarchy. This can take a few seconds.';try{const type=document.querySelector('#type').value.split(' ')[0];const response=await fetch('/api/trace',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain:document.querySelector('#domain').value,type})});const data=await response.json();if(!response.ok)throw new Error(data.error);render(data);statusEl.textContent=`Trace finished. ${data.steps.length} nameservers answered.`}catch(error){statusEl.className='status error';statusEl.textContent=error.message||'The trace failed.'}finally{go.disabled=false;go.textContent='Trace this domain'}});
</script></body></html>'''


class AppHandler(BaseHTTPRequestHandler):
    def send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if urlparse(self.path).path != "/":
            self.send_error(404)
            return
        body = HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if urlparse(self.path).path != "/api/trace":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 4096:
                raise ValueError("Request is too large.")
            payload = json.loads(self.rfile.read(length))
            self.send_json(trace_dns(payload.get("domain", ""), payload.get("type", "A")))
        except (ValueError, json.JSONDecodeError) as error:
            self.send_json({"error": str(error)}, 400)
        except Exception as error:
            self.send_json({"error": str(error)}, 502)

    def log_message(self, format, *args):
        print(f"[{self.log_date_time_string()}] {format % args}")


def run(host="0.0.0.0", port=None):
    port = port or int(os.environ.get("PORT", "8000"))
    print(f"DNS Field Guide running at http://{host}:{port}")
    ThreadingHTTPServer((host, port), AppHandler).serve_forever()


if __name__ == "__main__":
    run()
