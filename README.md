<div align="center">

# 🛡️ MSF-Assistant v3

**Herramienta web de automatización de pentesting construida sobre Metasploit Framework**

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.x-lightgrey?style=flat-square&logo=flask)
![Metasploit](https://img.shields.io/badge/Metasploit-Framework-red?style=flat-square)
![Kali Linux](https://img.shields.io/badge/Kali-Linux-557C94?style=flat-square&logo=kalilinux)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Educational](https://img.shields.io/badge/Purpose-Educational-orange?style=flat-square)

> Interfaz web local que automatiza el flujo completo de un test de penetración: descubrimiento de red, selección y lanzamiento de exploits, generación de payloads con msfvenom y post-explotación — todo desde el navegador, ejecutándose en Kali Linux.

</div>

---

## 📋 Descripción

MSF-Assistant es una aplicación web Flask que actúa como capa de orquestación sobre Metasploit Framework. En lugar de escribir comandos manualmente en msfconsole, la herramienta guía al usuario por las fases de un pentest con una interfaz visual moderna, generando y ejecutando los comandos reales en el sistema.

Desarrollada como proyecto de portfolio para el aprendizaje de ciberseguridad ofensiva en entornos controlados.

---

## ✨ Funcionalidades

| Módulo | Descripción |
|--------|-------------|
| 🔍 **Escaneo de red** | Ejecuta `netdiscover` o `nmap` reales con output en tiempo real via Server-Sent Events |
| 🎯 **Selección de exploits** | Base de datos de 12 exploits con filtros por categoría, búsqueda por CVE/puerto/nombre |
| ⚙️ **Configuración automática** | Pre-rellena RHOSTS, LHOST y opciones al seleccionar target del escaneo |
| 🚀 **Lanzador Metasploit** | Genera scripts `.rc` y ejecuta `msfconsole -r` mostrando output en tiempo real |
| 💣 **Generador de payloads** | Interfaz para `msfvenom` con 10 tipos de payload, encoders y descarga directa |
| 🛡️ **Post-explotación** | Módulos post/, comandos Meterpreter y técnicas de escalada de privilegios |

---

## 🗂️ Exploits incluidos

| Exploit | CVE | Plataforma | Rank |
|---------|-----|-----------|------|
| Drupalgeddon2 | CVE-2018-7600 | Linux (Drupal 7/8) | Excellent |
| EternalBlue MS17-010 | CVE-2017-0144 | Windows 7/2008 | Excellent |
| MS08-067 NetAPI | CVE-2008-4250 | Windows XP/2003 | Excellent |
| UnrealIRCd Backdoor | CVE-2010-2075 | Linux (IRC) | Excellent |
| ProFTPd 1.3.3c Backdoor | CVE-2010-4221 | Linux (FTP) | Excellent |
| vsftpd 2.3.4 Backdoor | CVE-2011-2523 | Linux (FTP) | Excellent |
| Tomcat Manager Upload | CVE-2009-3843 | Java (Tomcat) | Excellent |
| Shellshock CGI | CVE-2014-6271 | Linux (Apache) | Excellent |
| Heartbleed | CVE-2014-0160 | SSL/TLS | Great |
| SSH Login Bruteforce | — | Universal | Good |
| MySQL Login Scanner | — | Linux/Windows | Good |
| Multi/Handler Listener | — | Universal | Excellent |

---

## 💣 Tipos de payload (msfvenom)

- Linux x86 / x64 ELF (Meterpreter reverse TCP)
- Windows x86 / x64 EXE (Meterpreter reverse TCP)
- PHP webshell
- Python reverse shell
- Bash one-liner
- Java WAR (Tomcat/JBoss)
- ASP.NET ASPX (IIS)
- PowerShell PS1

Soporte para encoders: `shikata_ga_nai`, `xor_dynamic`, `php/base64`, `unicode_mixed`.

---

## 🏗️ Arquitectura

```
msf-assistant/
├── app.py                  # Backend Flask — rutas, APIs, ejecución de comandos
├── templates/
│   └── index.html          # Frontend SPA — interfaz completa en un solo archivo
├── requirements.txt        # Dependencias Python
└── instalar.sh             # Script de instalación y arranque
```

**Stack técnico:**
- **Backend:** Python 3 + Flask, subprocess para ejecución de comandos, Server-Sent Events para streaming de output
- **Frontend:** HTML/CSS/JS vanilla, sin frameworks — interfaz hacker-themed con tema oscuro
- **Integración:** Metasploit Framework (msfconsole, msfvenom), nmap, netdiscover

---

## ⚙️ Instalación

### Requisitos
- Kali Linux (o cualquier distro con Metasploit instalado)
- Python 3.8+
- Metasploit Framework (`msfconsole`, `msfvenom`)
- nmap, netdiscover

### Instalación rápida

```bash
git clone https://github.com/Davidaah07/msf-assistant.git
cd msf-assistant
sudo bash instalar.sh
```

### Instalación manual

```bash
git clone https://github.com/Davidaah07/msf-assistant.git
cd msf-assistant
sudo pip3 install flask --break-system-packages
sudo python3 app.py
```

Abre el navegador en: **http://localhost:5000**

> ⚠️ Ejecutar con `sudo` es necesario para que netdiscover y nmap tengan permisos de red.

---

## 🔄 Flujo de uso

```
1. Escaneo de red
   └── netdiscover / nmap → hosts descubiertos → seleccionar target

2. Selección de exploit
   └── filtrar por categoría → leer descripción y CVE → seleccionar

3. Configuración
   └── RHOSTS y LHOST auto-rellenados → ajustar parámetros si necesario

4. Lanzar
   └── genera script .rc → ejecuta msfconsole → output en tiempo real

5. Payloads (flujo alternativo)
   └── elegir tipo → configurar LHOST/LPORT/encoder → generar → descargar

6. Post-explotación
   └── módulos post/ → comandos Meterpreter → escalada de privilegios
```

---

## 🧪 Entornos de prueba compatibles

| Máquina | Exploits recomendados |
|---------|-----------------------|
| **Metasploitable 2** | vsftpd, UnrealIRCd, Shellshock, SSH bruteforce, MySQL |
| **Metasploitable 3 (Ubuntu)** | Drupalgeddon2, ProFTPd, UnrealIRCd, Tomcat |
| **Windows 7 / XP VM** | EternalBlue, MS08-067 |
| **Cualquier Drupal 7/8** | Drupalgeddon2 |
| **Cualquier Tomcat con creds débiles** | Tomcat Manager Upload |

---

## 📸 Capturas

> *Añadir capturas de pantalla de la herramienta en uso*

---

## ⚠️ Aviso legal

Este proyecto ha sido desarrollado con **fines exclusivamente educativos** para el aprendizaje de ciberseguridad ofensiva en entornos controlados.

**Está terminantemente prohibido** utilizar esta herramienta contra sistemas sin autorización explícita del propietario. El uso indebido puede constituir un delito según la legislación vigente en España y en la mayoría de países.

El autor no se hace responsable del uso indebido de este software. Úsalo únicamente en:
- Tus propias máquinas virtuales
- Entornos de laboratorio como Metasploitable, HackTheBox, TryHackMe
- Sistemas para los que tienes autorización escrita

---

## 📄 Licencia

MIT License — ver [LICENSE](LICENSE) para más detalles.

---

<div align="center">
Desarrollado para aprendizaje de ciberseguridad | Kali Linux + Metasploit Framework
</div>
