import datetime  # para calcular a idade do domínio
import json
import os
import re
import socket
import ssl
import subprocess  # para executar o comando whois no sistema
import threading
import time
from collections import deque
from urllib.parse import urlparse

import requests  # para consultar a API do VirusTotal
from flask import Flask, render_template, request


app = Flask(__name__)

# A chave da API nunca deve ficar hardcoded no código.
VT_API_KEY = os.getenv("VT_API_KEY")
GSB_API_KEY = os.getenv("GSB_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# Cache do VirusTotal:
# - mantém resultados em memória para resposta rápida
# - persiste em JSON para sobreviver a reinícios da aplicação
VT_CACHE = {}
VT_CACHE_TTL_SECONDS = 3600  # 1 hora
VT_CACHE_MAX_ENTRIES = 1000
VT_CACHE_FILE = os.path.join(os.path.dirname(__file__), "vt_cache.json")

# Cache do AbuseIPDB:
# A reputação de IP é usada apenas como sinal de apoio e pode envolver IPs
# partilhados por muitos sites legítimos. Guardar resultados durante 1 hora
# evita chamadas repetidas para o mesmo IP e ajuda a respeitar limites da API.
ABUSEIPDB_CACHE = {}
ABUSEIPDB_CACHE_TTL_SECONDS = 3600  # 1 hora
ABUSEIPDB_CACHE_MAX_ENTRIES = 1000
ABUSEIPDB_CACHE_FILE = os.path.join(os.path.dirname(__file__), "abuseipdb_cache.json")

# Rate limiting por IP do cliente:
# - 2 segundos mínimos entre pedidos para travar spam imediato
# - 8 pedidos por minuto para impedir abuso sem afetar uso normal
IP_DATA = {}
IP_COOLDOWN_SECONDS = 2
IP_RATE_LIMIT = 8
IP_RATE_WINDOW_SECONDS = 60

# Rate limiter simples em memória.
# Guardamos os timestamps das últimas chamadas reais ao VirusTotal
# para nunca ultrapassar 4 pedidos por minuto.
VT_RATE_LIMIT = 4
VT_RATE_WINDOW_SECONDS = 60
VT_REQUEST_TIMESTAMPS = deque()

# Locks para evitar race conditions se a app receber vários requests ao mesmo tempo.
VT_CACHE_LOCK = threading.Lock()
VT_RATE_LIMIT_LOCK = threading.Lock()
ABUSEIPDB_CACHE_LOCK = threading.Lock()
IP_RATE_LIMIT_LOCK = threading.Lock()

translations = {
    "pt": {
        "page_title": "Verificador de Segurança de Sites",
        "title": "Verificador de Segurança de Sites",
        "subtitle": "Verifique sinais comuns de risco antes de visitar um link.",
        "input_placeholder": "Insira um link para verificar",
        "button_text": "Verificar",
        "checking_text": "A verificar...",
        "language_selector": "Seletor de idioma",
        "language_en": "Inglês",
        "language_pt": "Português",
        "language_es": "Espanhol",
        "result_title": "Resultado",
        "security_score": "Pontuação de Segurança",
        "analyzed_link": "Link analisado",
        "problems_found": "Problemas encontrados",
        "information": "Informações",
        "no_issues": "Nenhum problema encontrado, o site parece seguro.",
        "status_low": "🟢 Baixo risco",
        "status_suspicious": "🟡 Suspeito",
        "status_danger": "🔴 Perigoso",
        "site_safe": "O site parece seguro com base nas verificações realizadas.",
        "site_suspicious": "O site apresenta alguns sinais suspeitos.",
        "site_danger": "O site apresenta riscos significativos.",
        "rate_too_fast": "Estás a fazer pedidos demasiado rápidos. Tenta novamente em alguns segundos.",
        "rate_limit_exceeded": "Limite de pedidos excedido. Tenta novamente daqui a 1 minuto.",
        "empty_url": "Não foi inserido nenhum link.",
        "https_missing": "O site não usa HTTPS.",
        "invalid_url": "O link parece inválido.",
        "suspicious_domain_format": "O nome do site parece estranho ou imitado (possível phishing).",
        "domain_created": "Domínio criado em {date} ({age} dias)",
        "domain_recent": "Domínio muito recente (menos de 6 meses). Possível phishing.",
        "whois_timeout": "A verificação WHOIS demorou demasiado tempo.",
        "whois_failed": "Não foi possível concluir a verificação WHOIS.",
        "ssl_valid": "Certificado SSL válido.",
        "ssl_invalid": "O certificado SSL é inválido ou não confiável.",
        "virustotal_malicious": "O domínio foi identificado como malicioso por sistemas de segurança.",
        "virustotal_suspicious": "O domínio é considerado suspeito por alguns sistemas.",
        "virustotal_unavailable": "VirusTotal temporariamente indisponível.",
        "gsb_malicious": "O site foi identificado como perigoso (Google Safe Browsing).",
        "gsb_unavailable": "Google Safe Browsing indisponível.",
        "vt_skipped_invalid": "A verificação no VirusTotal foi ignorada porque o link é inválido.",
        "vt_skipped_risky": "A verificação no VirusTotal foi ignorada porque já existem vários sinais locais de risco.",
        "abuseipdb_unavailable": "AbuseIPDB indisponível.",
        "abuseipdb_ip_suspicious": "O IP associado ao domínio tem histórico de atividade suspeita.",
        "abuseipdb_ip_reports": "O IP tem alguns relatórios, mas não é altamente suspeito.",
        "abuseipdb_dns_failed": "Não foi possível resolver o IP do domínio para análise AbuseIPDB.",
    },
    "en": {
        "page_title": "Website Safety Checker",
        "title": "Website Safety Checker",
        "subtitle": "Check a link for common warning signs before you visit.",
        "input_placeholder": "Enter a link to check",
        "button_text": "Check",
        "checking_text": "Checking...",
        "language_selector": "Language selector",
        "language_en": "English",
        "language_pt": "Portuguese",
        "language_es": "Spanish",
        "result_title": "Result",
        "security_score": "Security Score",
        "analyzed_link": "Analyzed link",
        "problems_found": "Problems found",
        "information": "Information",
        "no_issues": "No issues found, site appears safe.",
        "status_low": "🟢 Low risk",
        "status_suspicious": "🟡 Suspicious",
        "status_danger": "🔴 Dangerous",
        "site_safe": "The site appears safe based on the checks performed.",
        "site_suspicious": "The site shows some suspicious signs.",
        "site_danger": "The site shows significant risks.",
        "rate_too_fast": "You are making requests too quickly. Try again in a few seconds.",
        "rate_limit_exceeded": "Request limit exceeded. Try again in 1 minute.",
        "empty_url": "No link was entered.",
        "https_missing": "The site does not use HTTPS.",
        "invalid_url": "The link appears to be invalid.",
        "suspicious_domain_format": "The site name looks unusual or imitated (possible phishing).",
        "domain_created": "Domain created on {date} ({age} days)",
        "domain_recent": "Domain is very recent (less than 6 months). Possible phishing.",
        "whois_timeout": "The WHOIS check took too long.",
        "whois_failed": "The WHOIS check could not be completed.",
        "ssl_valid": "Valid SSL certificate.",
        "ssl_invalid": "The SSL certificate is invalid or not trusted.",
        "virustotal_malicious": "The domain was identified as malicious by security systems.",
        "virustotal_suspicious": "The domain is considered suspicious by some systems.",
        "virustotal_unavailable": "VirusTotal is temporarily unavailable.",
        "gsb_malicious": "The site was identified as dangerous (Google Safe Browsing).",
        "gsb_unavailable": "Google Safe Browsing is unavailable.",
        "vt_skipped_invalid": "The VirusTotal check was skipped because the link is invalid.",
        "vt_skipped_risky": "The VirusTotal check was skipped because there are already several local risk signals.",
        "abuseipdb_unavailable": "AbuseIPDB is unavailable.",
        "abuseipdb_ip_suspicious": "The IP associated with the domain has a history of suspicious activity.",
        "abuseipdb_ip_reports": "The IP has some reports, but is not highly suspicious.",
        "abuseipdb_dns_failed": "Could not resolve the domain IP for AbuseIPDB analysis.",
    },
    "es": {
        "page_title": "Verificador de Seguridad de Sitios",
        "title": "Verificador de Seguridad de Sitios",
        "subtitle": "Comprueba señales comunes de riesgo antes de visitar un enlace.",
        "input_placeholder": "Introduce un enlace para comprobar",
        "button_text": "Comprobar",
        "checking_text": "Verificando...",
        "language_selector": "Selector de idioma",
        "language_en": "Inglés",
        "language_pt": "Portugués",
        "language_es": "Español",
        "result_title": "Resultado",
        "security_score": "Puntuación de Seguridad",
        "analyzed_link": "Enlace analizado",
        "problems_found": "Problemas encontrados",
        "information": "Información",
        "no_issues": "No se encontraron problemas, el sitio parece seguro.",
        "status_low": "🟢 Bajo riesgo",
        "status_suspicious": "🟡 Sospechoso",
        "status_danger": "🔴 Peligroso",
        "site_safe": "El sitio parece seguro según las comprobaciones realizadas.",
        "site_suspicious": "El sitio presenta algunas señales sospechosas.",
        "site_danger": "El sitio presenta riesgos significativos.",
        "rate_too_fast": "Estás haciendo solicitudes demasiado rápido. Inténtalo de nuevo en unos segundos.",
        "rate_limit_exceeded": "Límite de solicitudes excedido. Inténtalo de nuevo en 1 minuto.",
        "empty_url": "No se introdujo ningún enlace.",
        "https_missing": "El sitio no usa HTTPS.",
        "invalid_url": "El enlace parece inválido.",
        "suspicious_domain_format": "El nombre del sitio parece extraño o imitado (posible phishing).",
        "domain_created": "Dominio creado el {date} ({age} días)",
        "domain_recent": "Dominio muy reciente (menos de 6 meses). Posible phishing.",
        "whois_timeout": "La comprobación WHOIS tardó demasiado.",
        "whois_failed": "No se pudo completar la comprobación WHOIS.",
        "ssl_valid": "Certificado SSL válido.",
        "ssl_invalid": "El certificado SSL es inválido o no es confiable.",
        "virustotal_malicious": "El dominio fue identificado como malicioso por sistemas de seguridad.",
        "virustotal_suspicious": "El dominio es considerado sospechoso por algunos sistemas.",
        "virustotal_unavailable": "VirusTotal no está disponible temporalmente.",
        "gsb_malicious": "El sitio fue identificado como peligroso (Google Safe Browsing).",
        "gsb_unavailable": "Google Safe Browsing no está disponible.",
        "vt_skipped_invalid": "La comprobación en VirusTotal se omitió porque el enlace es inválido.",
        "vt_skipped_risky": "La comprobación en VirusTotal se omitió porque ya hay varias señales locales de riesgo.",
        "abuseipdb_unavailable": "AbuseIPDB no está disponible.",
        "abuseipdb_ip_suspicious": "La IP asociada al dominio tiene historial de actividad sospechosa.",
        "abuseipdb_ip_reports": "La IP tiene algunos reportes, pero no es altamente sospechosa.",
        "abuseipdb_dns_failed": "No se pudo resolver la IP del dominio para el análisis de AbuseIPDB.",
    },
}


def get_lang():
    lang = request.form.get("lang") or request.args.get("lang", "pt")
    if lang not in translations:
        return "pt"
    return lang


def t(key, lang):
    return translations.get(lang, translations["pt"]).get(key, key)


def render_index(lang, **context):
    return render_template(
        "index.html",
        lang=lang,
        translations=translations,
        t=lambda key: t(key, lang),
        **context,
    )


def normalize_domain(netloc):
    domain = (netloc or "").split(":")[0].lower().strip()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def is_valid_domain(domain):
    return bool(domain and "." in domain and re.fullmatch(r"[a-z0-9.-]+", domain))


def load_persistent_virustotal_cache():
    if not os.path.exists(VT_CACHE_FILE):
        return

    try:
        with open(VT_CACHE_FILE, "r", encoding="utf-8") as cache_file:
            file_cache = json.load(cache_file)

        if not isinstance(file_cache, dict):
            return

        now = time.time()
        valid_entries = {}

        for domain, entry in file_cache.items():
            if not isinstance(entry, dict):
                continue

            expires_at = entry.get("expires_at")
            data = entry.get("data")
            if not isinstance(expires_at, (int, float)) or not isinstance(data, dict):
                continue

            if expires_at > now:
                valid_entries[domain] = {
                    "expires_at": expires_at,
                    "data": data,
                }

        with VT_CACHE_LOCK:
            VT_CACHE.clear()
            VT_CACHE.update(valid_entries)
            trim_virustotal_cache_locked()
            save_virustotal_cache_locked()
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        with VT_CACHE_LOCK:
            VT_CACHE.clear()


def save_virustotal_cache_locked():
    with open(VT_CACHE_FILE, "w", encoding="utf-8") as cache_file:
        json.dump(VT_CACHE, cache_file, ensure_ascii=False, indent=2)


def trim_virustotal_cache_locked():
    now = time.time()

    expired_domains = [
        domain
        for domain, entry in VT_CACHE.items()
        if not isinstance(entry, dict) or entry.get("expires_at", 0) <= now
    ]
    for domain in expired_domains:
        VT_CACHE.pop(domain, None)

    if len(VT_CACHE) <= VT_CACHE_MAX_ENTRIES:
        return

    sorted_domains = sorted(
        VT_CACHE.items(),
        key=lambda item: item[1].get("expires_at", 0),
        reverse=True,
    )
    VT_CACHE.clear()
    VT_CACHE.update(dict(sorted_domains[:VT_CACHE_MAX_ENTRIES]))


def cleanup_and_persist_virustotal_cache():
    with VT_CACHE_LOCK:
        trim_virustotal_cache_locked()
        try:
            save_virustotal_cache_locked()
        except OSError:
            pass


def load_persistent_abuseipdb_cache():
    if not os.path.exists(ABUSEIPDB_CACHE_FILE):
        return

    try:
        with open(ABUSEIPDB_CACHE_FILE, "r", encoding="utf-8") as cache_file:
            file_cache = json.load(cache_file)

        if not isinstance(file_cache, dict):
            return

        now = time.time()
        valid_entries = {}

        for ip, entry in file_cache.items():
            if not isinstance(entry, dict):
                continue

            expires_at = entry.get("expires_at")
            data = entry.get("data")
            if not isinstance(expires_at, (int, float)) or not isinstance(data, int):
                continue

            if expires_at > now:
                valid_entries[ip] = {
                    "expires_at": expires_at,
                    "data": data,
                }

        with ABUSEIPDB_CACHE_LOCK:
            ABUSEIPDB_CACHE.clear()
            ABUSEIPDB_CACHE.update(valid_entries)
            trim_abuseipdb_cache_locked()
            save_abuseipdb_cache_locked()
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        with ABUSEIPDB_CACHE_LOCK:
            ABUSEIPDB_CACHE.clear()


def save_abuseipdb_cache_locked():
    with open(ABUSEIPDB_CACHE_FILE, "w", encoding="utf-8") as cache_file:
        json.dump(ABUSEIPDB_CACHE, cache_file, ensure_ascii=False, indent=2)


def trim_abuseipdb_cache_locked():
    now = time.time()

    expired_ips = [
        ip
        for ip, entry in ABUSEIPDB_CACHE.items()
        if not isinstance(entry, dict) or entry.get("expires_at", 0) <= now
    ]
    for ip in expired_ips:
        ABUSEIPDB_CACHE.pop(ip, None)

    if len(ABUSEIPDB_CACHE) <= ABUSEIPDB_CACHE_MAX_ENTRIES:
        return

    sorted_ips = sorted(
        ABUSEIPDB_CACHE.items(),
        key=lambda item: item[1].get("expires_at", 0),
        reverse=True,
    )
    ABUSEIPDB_CACHE.clear()
    ABUSEIPDB_CACHE.update(dict(sorted_ips[:ABUSEIPDB_CACHE_MAX_ENTRIES]))


def cleanup_and_persist_abuseipdb_cache():
    with ABUSEIPDB_CACHE_LOCK:
        trim_abuseipdb_cache_locked()
        try:
            save_abuseipdb_cache_locked()
        except OSError:
            pass


def ssl_check_advanced(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain):
                return True
    except Exception:
        return False


def get_cached_virustotal_result(domain):
    now = time.time()

    with VT_CACHE_LOCK:
        cached_entry = VT_CACHE.get(domain)
        if not cached_entry:
            return None

        if cached_entry["expires_at"] <= now:
            VT_CACHE.pop(domain, None)
            try:
                save_virustotal_cache_locked()
            except OSError:
                pass
            return None

        return cached_entry["data"]


def store_cached_virustotal_result(domain, vt_stats):
    with VT_CACHE_LOCK:
        VT_CACHE[domain] = {
            "expires_at": time.time() + VT_CACHE_TTL_SECONDS,
            "data": vt_stats,
        }
        trim_virustotal_cache_locked()
        try:
            save_virustotal_cache_locked()
        except OSError:
            pass


def wait_for_virustotal_slot():
    # Requests servidos do cache não contam para o limite.
    # Apenas chamadas reais à API passam por esta fila de controlo.
    while True:
        now = time.time()

        with VT_RATE_LIMIT_LOCK:
            while VT_REQUEST_TIMESTAMPS and now - VT_REQUEST_TIMESTAMPS[0] >= VT_RATE_WINDOW_SECONDS:
                VT_REQUEST_TIMESTAMPS.popleft()

            if len(VT_REQUEST_TIMESTAMPS) < VT_RATE_LIMIT:
                VT_REQUEST_TIMESTAMPS.append(now)
                return

            sleep_seconds = VT_RATE_WINDOW_SECONDS - (now - VT_REQUEST_TIMESTAMPS[0])

        time.sleep(max(sleep_seconds, 0.1))


def get_cached_abuseipdb_result(ip):
    now = time.time()

    with ABUSEIPDB_CACHE_LOCK:
        cached_entry = ABUSEIPDB_CACHE.get(ip)
        if not cached_entry:
            return None

        if cached_entry["expires_at"] <= now:
            ABUSEIPDB_CACHE.pop(ip, None)
            try:
                save_abuseipdb_cache_locked()
            except OSError:
                pass
            return None

        return cached_entry["data"]


def store_cached_abuseipdb_result(ip, abuse_score):
    with ABUSEIPDB_CACHE_LOCK:
        ABUSEIPDB_CACHE[ip] = {
            "expires_at": time.time() + ABUSEIPDB_CACHE_TTL_SECONDS,
            "data": abuse_score,
        }
        trim_abuseipdb_cache_locked()
        try:
            save_abuseipdb_cache_locked()
        except OSError:
            pass


def check_virustotal(domain):
    # 1. Não tenta chamar a API se faltar configuração ou o domínio for inválido.
    if not VT_API_KEY or not is_valid_domain(domain):
        return {"status": "indisponivel", "stats": None}

    # 2. Reutiliza resultados recentes do cache em memória/ficheiro.
    cached_stats = get_cached_virustotal_result(domain)
    if cached_stats is not None:
        return {"status": "cache", "stats": cached_stats}

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}  

    try:
        # 3. Antes de fazer uma chamada real, espera por uma vaga no rate limiter.
        wait_for_virustotal_slot()

        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code != 200:
            return {"status": "indisponivel", "stats": None}

        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]

        store_cached_virustotal_result(domain, stats)
        return {"status": "api", "stats": stats}
    except (requests.RequestException, KeyError, TypeError, ValueError):
        return {"status": "indisponivel", "stats": None}


def check_ip_abuse(ip):
    if not ABUSEIPDB_API_KEY:
        return None

    cached_score = get_cached_abuseipdb_result(ip)
    if cached_score is not None:
        return cached_score

    endpoint = "https://api.abuseipdb.com/api/v2/check"
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
    }
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }

    try:
        response = requests.get(endpoint, params=params, headers=headers, timeout=5)
        if response.status_code != 200:
            return None

        data = response.json()
        abuse_score = data["data"]["abuseConfidenceScore"]
        if not isinstance(abuse_score, int):
            return None

        store_cached_abuseipdb_result(ip, abuse_score)
        return abuse_score
    except (requests.RequestException, KeyError, TypeError, ValueError):
        return None


def check_google_safe_browsing(url):
    # Fallback de reputação: só é usado quando o VirusTotal não consegue responder.
    # A API do Google Safe Browsing recebe o URL completo e devolve "matches"
    # quando identifica malware ou engenharia social.
    if not GSB_API_KEY:
        return None

    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    params = {"key": GSB_API_KEY}
    payload = {
        "client": {
            "clientId": "checklinks",
            "clientVersion": "1.0",
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = requests.post(endpoint, params=params, json=payload, timeout=5)
        if response.status_code != 200:
            return None

        data = response.json()
        return bool(data.get("matches"))
    except (requests.RequestException, ValueError, TypeError):
        # Qualquer falha de rede ou parsing devolve None para não quebrar a app.
        return None


def should_query_virustotal(invalid_url, problems):
    # Lógica de decisão:
    # - nunca consulta para URLs inválidos
    # - ainda consulta quando há poucos sinais locais, para ganhar contexto externo
    # - evita a chamada apenas quando já existem vários problemas claros
    if invalid_url:
        return False

    return len(problems) < 3


def check_client_rate_limit(ip_address, lang):
    # Este limitador fica em memória para ser leve e rápido. Em produção com
    # vários processos/servidores, Redis ou outro armazenamento partilhado seria
    # necessário para aplicar limites globais.
    now = time.time()

    with IP_RATE_LIMIT_LOCK:
        ip_entry = IP_DATA.setdefault(
            ip_address,
            {
                "last_request": 0,
                "requests": [],
            },
        )

        if now - ip_entry["last_request"] < IP_COOLDOWN_SECONDS:
            return t("rate_too_fast", lang)

        recent_requests = [
            timestamp
            for timestamp in ip_entry["requests"]
            if now - timestamp < IP_RATE_WINDOW_SECONDS
        ]

        if len(recent_requests) >= IP_RATE_LIMIT:
            ip_entry["requests"] = recent_requests
            return t("rate_limit_exceeded", lang)

        recent_requests.append(now)
        ip_entry["requests"] = recent_requests
        ip_entry["last_request"] = now

    return None


load_persistent_virustotal_cache()
cleanup_and_persist_virustotal_cache()
load_persistent_abuseipdb_cache()
cleanup_and_persist_abuseipdb_cache()


@app.route("/")
def home():
    lang = get_lang()
    return render_index(lang)


@app.route("/check", methods=["POST"])
def check():
    lang = get_lang()
    client_ip = request.remote_addr or "unknown"
    rate_limit_message = check_client_rate_limit(client_ip, lang)
    if rate_limit_message:
        return rate_limit_message

    url = request.form.get("url", "").strip()

    if not url:
        return t("empty_url", lang)

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    parsed_url = urlparse(url)

    score = 0
    risk_score = 100
    problems = []
    info = []

    domain = normalize_domain(parsed_url.netloc)
    invalid_url = parsed_url.scheme not in {"http", "https"} or not is_valid_domain(domain)

    if parsed_url.scheme != "https":
        score += 1
        risk_score -= 21
        problems.append(t("https_missing", lang))

    if invalid_url:
        score += 1
        risk_score -= 21
        problems.append(t("invalid_url", lang))

    if url.count("-") > 2 or url.count("_") > 3 or url.count(".") > 5:
        score += 1
        risk_score -= 10
        problems.append(t("suspicious_domain_format", lang))

    # WHOIS local: ajuda a decidir se vale a pena consultar serviços externos.
    if not invalid_url:
        try:
            result = subprocess.run(
                ["whois", domain],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = result.stdout

            match = re.search(r"(Creation Date|created):\s*([0-9\-T:\.Z]+)", output, re.IGNORECASE)
            if match:
                creation_str = match.group(2).replace("Z", "")
                creation_date = datetime.datetime.strptime(creation_str, "%Y-%m-%dT%H:%M:%S")
                age = (datetime.datetime.now() - creation_date).days

    

                info.append(t("domain_created", lang).format(date=creation_date.date(), age=age))

                if age < 180:
                    score += 1
                    risk_score -= 10
                    problems.append(t("domain_recent", lang))
        except subprocess.TimeoutExpired:
            info.append(t("whois_timeout", lang))
        except Exception as error:
            print("Erro WHOIS:", error)
            info.append(t("whois_failed", lang))

    if not invalid_url:
        if ssl_check_advanced(domain):
            info.append(t("ssl_valid", lang))
        else:
            # Penalização reduzida para não tornar o resultado excessivamente agressivo.
            score += 1
            risk_score -= 15
            problems.append(t("ssl_invalid", lang))

    should_call_vt = should_query_virustotal(invalid_url, problems)

    if should_call_vt:
        vt_result = check_virustotal(domain)
        vt_stats = vt_result["stats"]

        if vt_stats:
            malicious = vt_stats.get("malicious", 0)
            suspicious = vt_stats.get("suspicious", 0)

            if malicious > 3:  # limiar mais alto para evitar falsos positivos
                score += 2
                risk_score -= 30
                problems.append(t("virustotal_malicious", lang))
            elif malicious > 0 and suspicious > 0:
                score += 1
                risk_score -= 15
                problems.append(t("virustotal_suspicious", lang))
        else:
            info.append(t("virustotal_unavailable", lang))

            # Fallback: se o VirusTotal falhar, consultamos o Google Safe Browsing
            # para manter uma segunda camada de deteção sem alterar a lógica principal.
            gsb_result = check_google_safe_browsing(url)
            if gsb_result is True:
                score += 2
                risk_score -= 30
                problems.append(t("gsb_malicious", lang))
            elif gsb_result is None:
                info.append(t("gsb_unavailable", lang))
    elif invalid_url:
        info.append(t("vt_skipped_invalid", lang))
    else:
        info.append(t("vt_skipped_risky", lang))

    # Reputação de IP é um sinal auxiliar: só consultamos o AbuseIPDB quando
    # o domínio é válido e já existe pelo menos um problema. Isto evita falsos
    # positivos em alojamentos partilhados (Cloudflare, AWS, etc.) e reduz o
    # número de chamadas à API gratuita.
    if not invalid_url and score >= 1:
        try:
            ip = socket.gethostbyname(domain)
            ip_abuse_score = check_ip_abuse(ip)

            # A pontuação do IP nunca domina a decisão final. Um score alto no
            # AbuseIPDB acrescenta apenas 1 ponto; scores baixos/médios entram
            # como informação contextual porque podem refletir IPs partilhados.
            if ip_abuse_score is None:
                info.append(t("abuseipdb_unavailable", lang))
            elif ip_abuse_score > 50:
                score += 1
                risk_score -= 10
                problems.append(t("abuseipdb_ip_suspicious", lang))
            elif ip_abuse_score >= 1:
                info.append(t("abuseipdb_ip_reports", lang))
        except socket.gaierror:
            info.append(t("abuseipdb_dns_failed", lang))
        except OSError:
            info.append(t("abuseipdb_unavailable", lang))

    risk_score = max(0, min(100, risk_score))

    if risk_score >= 80:
        status_key = "low"
        status = t("status_low", lang)
        risk_explanation = t("site_safe", lang)
    elif risk_score >= 60:
        status_key = "suspicious"
        status = t("status_suspicious", lang)
        risk_explanation = t("site_suspicious", lang)
    else:
        status_key = "danger"
        status = t("status_danger", lang)
        risk_explanation = t("site_danger", lang)

    return render_index(
        lang,
        status=status,
        status_key=status_key,
        risk_score=risk_score,
        risk_explanation=risk_explanation,
        url=url,
        problems=problems,
        info=info,
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
