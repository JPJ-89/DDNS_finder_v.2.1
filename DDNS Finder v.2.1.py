#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess
import sys
import os
import json
import time
import re

# Intentar importar requests solo si se va a usar DoH (opción 1)
try:
    import requests
except Exception:
    requests = None

# COLORES:
BLANCO = "\033[1;37m"
VERDE = "\033[1;32m"
ROJO = "\033[1;31m"
NARANJA = "\033[1;38;5;208m"
AMARILLO = "\033[1;33m"
AZUL = "\033[0;34m"  
VERDE_FINO = "\033[32m"
NARANJA_FINO = "\033[33m"
ROJO_FINO = "\033[31m"
NC = "\033[0m"  # SIN COLOR
      

# LIMPIAR PANTALLA
os.system("clear")

print(rf"""{VERDE}
  ____    ____    _   _   ____      _____   ___   _   _   ____    _____   ____  
 |  _ \  |  _ \  | \ | | / ___|    |  ___| |_ _| | \ | | |  _ \  | ____| |  _ \ 
 | | | | | | | | |  \| | \___ \    | |_     | |  |  \| | | | | | |  _|   | |_) |
 | |_| | | |_| | | |\  |  ___) |   |  _|    | |  | |\  | | |_| | | |___  |  _ < 
 |____/  |____/  |_| \_| |____/    |_|     |___| |_| \_| |____/  |_____| |_| \_\
 
 Quick DDNS subdomain discovery vía DNS over HTTPS and ping.                v.2.1{NC}
{AMARILLO}
 Autor: Jon Pérez Jorge                                                       
 Contacto: jonperezjorge@gmail.com{NC}
{ROJO_FINO}
 Advertencia: Esta herramienta debe usarse de manera responsable. 
 El autor no asume responsabilidad por un uso indebido de la misma.
{NC}

""")

try:
    subdomain = input(f"{BLANCO}> Introduce el hostname del dominio DDNS que deseas localizar: {NC}")
except KeyboardInterrupt:
    print()
    sys.exit(1)

# MENU
print()
print(f"{BLANCO}> Elige método de búsqueda:{NC}")
print()  # Línea en blanco
print(f"1) {VERDE_FINO}[Reconocimiento pasivo]{NC} --> DNS over HTTPS (Google + Cloudflare)")
print(f"2) {ROJO_FINO}[Reconocimiento activo]{NC} --> Echo ICMP (Ping)")
print()
try:
    opcion = input("Selecciona una opción (1/2): ").strip()
except KeyboardInterrupt:
    print()
    sys.exit(1)

if opcion not in ("1", "2"):
    print("Opción no válida. Saliendo.")
    sys.exit(1)

# LISTADO DE SEGUNDA PARTE DEL DOMINIO:
domains = [

#Falsos positivos (siempre resuelven):
# .ddns.net
# .homeip.net
# .mine.nu
# dnsalias.com
# dynalias.net

#RESTO:

".dyndns.org",
".ddns.net",
".no-ip.com",
".dyndns.tv",
".dyndns.info",
".homeip.net",
".dyndns.biz",
".mine.nu",
".dyn.com",
".cam.dyn.com",
".router.dyn.com",
".ddns.dyn.com",
".dnsalias.com",
".dynalias.com",
".dynalias.net",
".dynalias.org",
".dynathome.net",
".dyndns-at-home.com",
".dyndns-at-work.com",
".dyndns-blog.com",
".dyndns-free.com",
".dyndns-home.com",
".dyndns-mail.com",
".dyndns-office.com",
".dyndns-pics.com",
".dyndns-remote.com",
".dyndns-server.com",
".dyndns-web.com",
".dyndns-wiki.com",
".dyndns-work.com",
".dyndns.ws",
".dyndns-ip.com",
".selfip.com",
".synology.me",
".tplinkdns.com",
".asuscomm.com",
".myqnapcloud.com",
".dahuaddns.com",
".dahuacc.com",
".axis-cam.com",
".panasonic-dns.net",
".ubnt.com",
".unifi.com",
".annkeddns.com",
".annke.com",
".swanddns.com",
".vstarcam.com",
".meraki.com",
".tendaddns.com",
".tenda.com",
".zyxelddns.com",
".zyxel.com",
".tplinkcloud.com",
".tuya.com",
".linksysddns.com",
".netgearddns.com",
".trendnetddns.com",
".ciscodyn.com",
".qnap.to",
".asustor.com",
".asustorddns.com",
".synologycloud.com",
".synology-dns.com",
".wdmycloud.com",
".seagatepersonalcloud.com",
".buffalodns.com",
".buffalo-nas.com",
".hik-connect.com",
".dahuacloud.com",
".reolinkcloud.com",
".foscamcloud.com",
".vivotekcloud.com",
".axis-communications.com",
".panasoniccloud.com",
".boschsecuritycloud.com",
".ubiquitiunifi.com",
".iotdyn.com",
".mydevicedns.com",
".dnsomatic.com",
".ydns.io",
".dynu.com",
".dynu.net",
".dnsexit.com",
".mynetname.net",
".sn.mynetname.net",
".homeiot.net",
".smarthomecloud.com",
".mydevices.com",
".smartip.io",
".cloudiot.net",
".dynrouter.com",
".hikonline.es",
".hik-online.com",
".hommax-ddns.com",
".freemyip.com",
".myhostdns.com",
".rapidddns.com",
".hi-ddns.com",
".hik-ddns.com",
".dvrdns.org",
".easyddns.com",
".dynhost.org",
".ddns360.com",
".no-ip.biz",
".no-ip.org",
".dyndns.tech",
".myddns.org",
".annkecam.com",
".honeywellddns.com",
".hikvisioncloud.com",
".dahuacloud.net",
".dahuatv.com",
".swanncloud.com",
".vstarcamcloud.com",
".foscamcloud.net",
".reolinkddns.net",
".vivotekddns.com",
".panasoniccloud.net",
".axisddns.com",
".boschddns.com",
".unifieddns.com",
".ubiquiticloud.com",
".tplinkddns.net",
".tp-linkcloud.com",
".asusddns.org",
".asustorcloud.com",
".qnapddns.org",
".qnapcloud.net",
".synologyddns.net",
".synologycloud.org",
".wdmycloud.net",
".seagatecloud.net",
".buffalodns.net",
".merakiddns.com",
".ciscoddns.com",
".trendnetcloud.com",
".netgearddns.net",
".dlinkcloud.net",
".zte-ddns.com",
".huawei-ddns.com",
".tpddns.com",
".homenetworkdns.com",
".ipcamcloud.net",
".nvrcloud.net",
".smarthomenet.com",
".iotdevicecloud.net",
".ipcamddns.net",
".nasddns.org",
".routercloud.net",
".homeiotcloud.com",
".dyndnsrouter.com",
".ddnsrouter.net",
".myhomeiot.com",
".home-devices.net",
".onvifcloud.com",
".iptvddns.net",
".cloudcams.net",
".camcloud.org",
".nvrddns.net",
".cctvcloud.net",
".securitycamera-cloud.com",
".homesurveillance.net",
".remoteipcam.com",
".cloudnas.net",
".home-network-cloud.com",
".home-dyndns.net",
".smartcamddns.com",
".smartsecuritycloud.com",
".videoclouddns.com",
".smartdvrcloud.com",
".myhomecctv.com",
".homeiotnetwork.com",
".smarthome-network.net",
".cloudsecuritycam.com",
".iotcloudservices.net",
".cloudnvr.net",
".reolink.com",
".reolinkddns.com",
".foscamddns.com",
".geovision.com.tw",
".ipcamddns.com",
".seeddns.com",
".dvrdns.net",
".camddns.com",
".nasddns.com",
".routerddns.com",
".dynuddns.com",
".noip.me",
".zapto.org",
".hopto.org",
".duckdns.org",
".afraid.org",
".dnsdynamic.org",
".he.net",
".dnsomb.com",
".ns01.net",
".ns02.net",
".ns03.biz",
".changeip.org",
".dynv6.com",
".dynv6.net",
".dnsupdater.net",
".ip-dns.com",
".ip-dns.net",
".publicvm.com",
".myddns.com",
".myddns.net",
".dns04.com",
".dns05.net",
".dnscloud.org",
".ns1.name",
".ns2.name",
".dyndns.pro",
".dynns.com",
".sitelic.com",
".dnsalias.info",
".myhome-server.de",
".myftp.org",
".myvnc.com",
".mydns.co.jp",
".dns.jp",
".dns123.org",
".dns777.net",
".remotewan.com",
".dyn-access.com",
".cam4ever.com",
".securitytcp.com",
".videoddns.com",
".nvrddns.com",
".onvifddns.com",
".iptvddns.com",
".smarthomedns.com",
".iotdns.net",
".m2mdns.com",
".azure-dns.com",
".gcpdns.com",
".dyncloud.org",
".privatedns.com",
".securedns.org",
".dnsfamily.com",
".dnshome.org",
".dnsoffice.net",
".workdns.biz",
".schoolisdns.com",
".universitydns.org",
".govdns.net",
".mildns.org",
".dyn53.com",
".dnsport.cc",
".internetdns.net",
".worlddns.org",
".eu.org",
".us.org",
".asia.com",
".eudns.org",
".dnscentral.net",
".dnsnode.com",
".dnsroot.com",
".cyberdns.com",
".techdns.org",
".future-dns.net",
".nextgendns.com",
".dnsfuture.org",
".dyncloud.net",
".dynamicip.cc",
".staticdns.org",
".dnsauto.net",
".smartdns.org",
".fastdns.com",
".speeddns.net",
".freedns.afraid.org",
".paydns.org",
".dns4less.com",
".dns4more.org",
".easydns.com",
".simpledns.net",
".securednshome.com",
".dnsfilter.com",
".familydns.org",
".adblockdns.com",
".pihole.org",
".nextdns.io",
".opendns.com",
".comododns.com",
".nortondns.com",
".yandexdns.com",
".dnswatch.info",
".dnsinspect.com",
".dnscheck.org",
".dnsbl.com",
".dnswhitelist.org",
".dnsredir.com",
".dnsalias.co.uk",
".dnsalias.pt",
".dnsalias.es",
".dnsalias.fr",
".dnsalias.de",
".dnsalias.it",
".dnsalias.uk",
".dnsalias.eu",
".dnsalias.world",
".dnsalias.global",
".dnsalias.tech",
".dnsalias.online",
".dnsalias.site",
".dnsalias.website",
".dnsalias.store",
".dnsalias.shop",
".dnsalias.app",
".dnsalias.dev",
".dnsalias.blog",
".dnsalias.wiki",
".dnsalias.fun",
".dnsalias.games",
".dnsalias.cloud",
".dnsalias.space",
".dnsalias.live",
".dnsalias.work",
".dnsalias.biz",
".dnsalias.pro",
".dnsalias.name",
".dnsalias.co",
".cloudip.io",
".freedyn.io",
".myhomeip.net",
".dynrouter.net",
".homeip.io",
".dynv6.org",
".changeip.net",
".dynaccess.net",
".dyncloud.co",
".mydevicecloud.com",
".ip4.me",
".myfritz.net",
".homefritz.com",
".remoteiot.com",
".iotddns.net",
".remotedevice.io",
".smarthomedns.net",
".smartipdns.com",
".nvrcloud.io",
".ipcamera.cloud",
".securitycam.cloud",
".cctvcloud.io",
".reolinkddns.io",
".hikcloud.net",
".hikvisionddns.com",
".dahuaddns.net",
".vivotekddns.net",
".tplinkddns.io",
".tplinkcloud.net",
".asusddns.net",
".qnapcloud.io",
".synologycloud.net",
".wdmycloud.io",
".seagatecloud.io",
".buffalodns.io",
".ubntcloud.net",
".unifi-ddns.com",
".zyxelcloud.com",
".tendaddns.net",
".merakiddns.net",
".ciscoddns.net",
".iotcloudservice.com",
".cloud4home.net",
".homeiotservice.com",
".myiotdevice.net",
".remoteiotdevice.com",
".smartdevicecloud.net",
".devicecloudservice.com",
".ipdevicecloud.net",
".homeiotcloud.io",
".camcloudservice.net",
".videocloudservice.com",
".myiotcloud.net",
".tinyddns.com",
".microddns.net",
".homeiotcloudservice.com",
".smartddns.net",
".device4home.com",
".cloudiotdevice.net",
".remotedevicenet.com",
".ip4iot.com",
".cloud4iot.net",
".homeautomationdns.com",
".smarthomeiot.net",
".iotdevicecloud.io",
".cam4iot.com",
".cctviot.net",
".securityiotcloud.com",
".videonetworkcloud.net",
".remotevideocam.com",
".nvr4home.com",
".myhomecctv.io",
".homevideonetwork.net",
".smarthomecam.io",
".iotcamcloud.net",
".iotsecuritycam.com",
".iotnvrcloud.net",
".homeautomationcloud.net",
".mydeviceiot.com",
".remoteiotcloud.com",
".tinycamcloud.net",
".microcamcloud.com",
".camnetworkcloud.io",
".securitycam4home.com",
".videonvrcloud.net",
".cctvcloudservice.com",
".cloudsecuritydevice.net",
".iotnetworkdevice.com",
".myiotdevicecloud.io",
".remotedevicemanagement.com",
".smarthomenetworkcloud.net",
".homeiotnetworkservice.com",
".smartdevicecloud.io",
".myiotservice.net",
".iotdevicehub.com",
".iotdevicehub.net",
".camdevicecloud.com",
".videodevicecloud.net",
".securitydevicecloud.io",
".clouddevicehub.net",
".iotcamerahub.com",
".nvrdevicecloud.net",
".hobby-site.com",
".hobby-site.org",
".home.dyndns.org",
".homedns.org",
".homeftp.net",
".homeftp.org",
".homelinux.com",
".homelinux.net",
".homelinux.org",
".homeunix.com",
".homeunix.net",
".homeunix.org",
".getmyip.com",
".gets-it.net",
".go.dyndns.org",
".gotdns.com",
".gotdns.org",
".at-band-camp.net",
".ath.cx",
".barrel-of-knowledge.info",
".barrell-of-knowledge.info",
".better-than.tv",
".blogdns.com",
".blogdns.net",
".blogdns.org",
".blogsite.org",
".boldlygoingnowhere.org",
".broke-it.net",
".buyshouses.net",
".cechire.com",
".dnsalias.net",
".dnsalias.org",
".dnsdojo.com",
".dnsdojo.net",
".dnsdojo.org",
".does-it.net",
".doesntexist.com",
".doesntexist.org",
".dontexist.com",
".dontexist.net",
".dontexist.org",
".doomdns.com",
".doomdns.org",
".dyn-o-saur.com",
".endofinternet.net",
".endofinternet.org",
".endoftheinternet.org",
".est-a-la-maison.com",
".est-a-la-masion.com",
".est-le-patron.com",
".est-mon-blogueur.com",
".for-better.biz",
".for-more.biz",
".for-our.info",
".for-some.biz",
".for-the.biz",
".forgot.her.name",
".forgot.his.name",
".ftpaccess.cc",
".fuettertdasnetz.de",
".game-host.org",
".game-server.cc",
".groks-the.info",
".groks-this.info",
".ham-radio-op.net",
".here-for-more.info",
".iamallama.com",
".in-the-band.net",
".is-a-anarchist.com",
".is-a-blogger.com",
".is-a-bookkeeper.com",
".is-a-bruinsfan.org",
".is-a-bulls-fan.com",
".is-a-candidate.org",
".is-a-caterer.com",
".is-a-celticsfan.org",
".is-a-chef.com",
".is-a-chef.net",
".is-a-chef.org",
".is-a-conservative.com",
".is-a-cpa.com",
".is-a-cubicle-slave.com",
".is-a-democrat.com",
".is-a-designer.com",
".is-a-doctor.com",
".is-a-financialadvisor.com",
".is-a-geek.com",
".is-a-geek.net",
".is-a-geek.org",
".is-a-green.com",
".is-a-guru.com",
".is-a-hard-worker.com",
".is-a-hunter.com",
".is-a-knight.org",
".is-a-landscaper.com",
".is-a-lawyer.com",
".is-a-liberal.com",
".is-a-libertarian.com",
".is-a-linux-user.org",
".is-a-llama.com",
".is-a-musician.com",
".is-a-nascarfan.com",
".is-a-nurse.com",
".is-a-painter.com",
".is-a-patsfan.org",
".is-a-personaltrainer.com",
".is-a-photographer.com",
".is-a-player.com",
".is-a-republican.com",
".is-a-rockstar.com",
".is-a-socialist.com",
".is-a-soxfan.org",
".is-a-student.com",
".is-a-teacher.com",
".is-a-techie.com",
".is-a-therapist.com",
".is-an-accountant.com",
".is-an-actor.com",
".is-an-actress.com",
".is-an-anarchist.com",
".is-an-artist.com",
".is-an-engineer.com",
".is-an-entertainer.com",
".is-by.us",
".is-certified.com",
".is-found.org",
".is-gone.com",
".is-into-anime.com",
".is-into-cars.com",
".is-into-cartoons.com",
".is-into-games.com",
".is-leet.com",
".is-lost.org",
".is-not-certified.com",
".is-saved.org",
".is-slick.com",
".is-uberleet.com",
".is-very-bad.org",
".is-very-evil.org",
".is-very-good.org",
".is-very-nice.org",
".is-very-sweet.org",
".is-with-theband.com",
".isa-geek.com",
".isa-geek.net",
".isa-geek.org",
".isa-hockeynut.com",
".issmarterthanyou.com",
".isteingeek.de",
".istmein.de",
".kicks-ass.net",
".kicks-ass.org",
".knowsitall.info",
".land-4-sale.us",
".lebtimnetz.de",
".leitungsen.de",
".likes-pie.com",
".likescandy.com",
".tunnelbroker.net",
".merseine.com",
".merseine.org",
".misconfused.org",
".mypets.ws",
".myphotos.cc",
".neat-url.com",
".office-on-the.net",
".on-the-web.tv",
".podzone.net",
".podzone.org",
".readmyblog.org",
".remotecam.nu",
".saves-the-whales.com",
".scrapper-site.net",
".scrapping.cc",
".selfip.biz",
".selfip.info",
".selfip.net",
".selfip.org",
".sells-for-less.com",
".sells-for-u.com",
".sells-it.net",
".sellsyourhome.org",
".servebbs.com",
".servebbs.net",
".servebbs.org",
".serveftp.net",
".serveftp.org",
".servegame.org",
".shacknet.biz",
".shacknet.us",
".simple-url.com",
".space-to-rent.com",
".stuff-4-sale.org",
".stuff-4-sale.us",
".teaches-yoga.com",
".thruhere.net",
".traeumtgerade.de",
".webhop.biz",
".webhop.info",
".webhop.net",
".webhop.org",
".worse-than.tv",
".writesthisblog.com",


]

# Arreglos para almacenar los dominios encontrados y los que podrían existir:
found_domains = {}   # dominio -> ip
maybe_domains = []

# Parámetros usados en ping para mantener la misma conducta que el script original:
PING_COUNT = "1"
PING_TIMEOUT = "5"  # utilizado como -W en ping de Linux

# Funciones DoH (opción 1)
def doh_query_google(host):
    try:
        r = requests.get("https://dns.google/resolve", params={"name": host, "type": "A"}, timeout=10)
        r.raise_for_status()
        j = r.json()
        ans = j.get("Answer", []) or []
        return [a.get("data") for a in ans if a.get("type") in (1, 28)]
    except Exception:
        return []

def doh_query_cloudflare(host):
    try:
        r = requests.get("https://cloudflare-dns.com/dns-query", params={"name": host, "type": "A"}, headers={"accept": "application/dns-json"}, timeout=10)
        r.raise_for_status()
        j = r.json()
        ans = j.get("Answer", []) or []
        return [a.get("data") for a in ans if a.get("type") in (1, 28)]
    except Exception:
        return []

def doh_query(host):
    results = []
    if requests is None:
        return {"error": "requests_no_instalado"}
    for func in (doh_query_google, doh_query_cloudflare):
        try:
            ips = func(host)
            for ip in ips:
                if ip and ip not in results:
                    results.append(ip)
        except Exception:
            pass
        time.sleep(0.05)
    return results

# Funciones Ping (opción 2)
# Funciones Ping (opción 2)
def do_ping(full_domain, index, total):
    print(f"\n[{int((index+1)/total*100)}%  -  {index+1}/{total}]")
    print(f"{BLANCO}Comprobando {full_domain}...{NC}\n")

    try:
        proc = subprocess.run(
            ["ping", "-c", PING_COUNT, "-W", PING_TIMEOUT, full_domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3
        )
        ping_output = (proc.stdout or "") + (proc.stderr or "")
        ping_status = proc.returncode
    except subprocess.TimeoutExpired as te:
        ping_output = (te.stdout or "") + (te.stderr or "") if hasattr(te, "stdout") else ""
        ping_status = 124
    except Exception as e:
        ping_output = str(e)
        ping_status = 1

    if ping_status == 124:
        print(f"{NARANJA}Tiempo de espera agotado para {full_domain} (timeout){NC}\n")
        maybe_domains.append(full_domain)
    elif ping_status == 0:
        print(f"{NC}{ping_output}{NC}")
        # extraer la primera IP del ping
        ip = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', ping_output)
        ip_text = ip.group(1) if ip else "?"
        print(f"{VERDE}{full_domain} existe! > ({ip_text}){NC}\n")
        found_domains[full_domain] = ip_text
    else:
        print(f"{NC}{ping_output}{NC}")
        print(f"{ROJO}{full_domain} no existe...{NC}\n")

    print(f"{AZUL}--------------------------------------------------------------------------------------------------{NC}")


# RECORRE CADA DOMINIO EN LA LISTA:
try:
    total_domains = len(domains)
    for idx, domain in enumerate(domains):
        full_domain = f"{subdomain}{domain}"

        if opcion == "1":
            # Mostrar porcentaje y progreso
            print(f"\n[{int((idx+1)/total_domains*100)}%  -  {idx+1}/{total_domains}]")
            print(f"{BLANCO}Comprobando {full_domain}...{NC}")
            print()  # Línea en blanco

            # DoH
            doh_resp = doh_query(full_domain)
            if isinstance(doh_resp, dict) and doh_resp.get("error") == "requests_no_instalado":
                print(f"{NC}Error: la librería 'requests' no está instalada. Instálala con: pip install requests{NC}")
                print(f"{AZUL}--------------------------------------------------------------------------------------------------{NC}")
                print(f"{ROJO}{full_domain} no existe...{NC}")
                print()  # Línea en blanco
                print(f"{AZUL}--------------------------------------------------------------------------------------------------{NC}")
                continue
            ips = doh_resp or []
            if ips:
                for ip in ips:
                    print(ip)
                print(f"{VERDE}{full_domain} existe!{NC}")
                print()  # Línea en blanco
                found_domains[full_domain] = ips  
            else:
                print(f"{ROJO}{full_domain} no existe...{NC}")
                print()  # Línea en blanco
            print(f"{AZUL}--------------------------------------------------------------------------------------------------{NC}")

        elif opcion == "2":
            do_ping(full_domain, idx, total_domains)

except KeyboardInterrupt:
    print(f"\n{ROJO}Cancelado por el usuario...{NC}\n")
finally:
    # Mostrar los resultados actuales
    print(f"{BLANCO}= RESULTADOS ={NC}")
    print()  # Línea en blanco
    if len(found_domains) > 0:
        print(f"{VERDE}Dominios encontrados:{NC}")
        for d, ips in found_domains.items():
            if isinstance(ips, list):
                print(f"{d} > ({', '.join(ips)})")
            else:
                print(f"{d} > ({ips})")
        print("")

    if len(maybe_domains) > 0:
        print(f"{NARANJA}Dominios con timeout:{NC}")
        for d in maybe_domains:
            print(d)



