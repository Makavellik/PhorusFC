from __future__ import annotations
import ssl, socket, re, json, time, datetime, logging, random, math
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.progress import track
from rich.table import Table
from rich.text import Text
from rich import box

# ---------------- CONFIGURACIÓN CAMALÉON ----------------
class FetchMode(str, Enum):
    """
    Modos de obtención de información.

    PASSIVE  → No interactúa activamente (OSINT puro, bajo riesgo)
    ACTIVE   → Interacción directa (peticiones, formularios, JS)
    HYBRID   → Combina pasivo + activo con límites claros
    CAMALEON → Se adapta dinámicamente según señales y riesgo
    """

    PASSIVE = "passive"
    ACTIVE = "active"
    HYBRID = "hybrid"
    CAMALEON = "camaleon"

    @property
    def is_passive(self) -> bool:
        return self in {FetchMode.PASSIVE}

    @property
    def is_active(self) -> bool:
        return self in {FetchMode.ACTIVE}

    @property
    def is_hybrid(self) -> bool:
        return self in {FetchMode.HYBRID}

    @property
    def is_camaleon(self) -> bool:
        return self in {FetchMode.CAMALEON}


class EnvironmentProfile:
    def __init__(
        self,
        risk_score: int = 0,
        external_calls: int = 0,
        suspicious_signals: int = 0,
        js_heavy: bool = False,
        forms_detected: bool = False
    ):
        self.risk_score = risk_score
        self.external_calls = external_calls
        self.suspicious_signals = suspicious_signals
        self.js_heavy = js_heavy
        self.forms_detected = forms_detected


def resolve_fetch_mode(
    mode: FetchMode,
    env: EnvironmentProfile
) -> FetchMode:
    """
    Decide el modo real de operación cuando FetchMode es CAMALEON.
    """

    if mode != FetchMode.CAMALEON:
        return mode

    # 🔴 Alto riesgo → pasivo
    if env.risk_score >= 70 or env.suspicious_signals >= 3:
        return FetchMode.PASSIVE

    # 🟡 JS pesado o formularios → híbrido
    if env.js_heavy or env.forms_detected:
        return FetchMode.HYBRID

    # 🟢 Bajo riesgo → activo controlado
    if env.external_calls <= 2 and env.risk_score < 30:
        return FetchMode.ACTIVE

    # ⚪ Default seguro
    return FetchMode.PASSIVE

def verdict_thresholds(mode: FetchMode) -> tuple[int, int]:
    """
    Devuelve thresholds (riesgo_medio, riesgo_alto)
    según el modo operativo.
    """
    if mode == FetchMode.PASSIVE:
        return 40, 70
    if mode == FetchMode.HYBRID:
        return 35, 65
    if mode == FetchMode.ACTIVE:
        return 30, 60
    return 35, 65

@dataclass
class AscensionConfig:
    http_timeout: int = 8
    tls_timeout: int = 6
    max_retries: int = 4
    max_html_kb: int = 1024
    user_agents: List[str] = field(default_factory=lambda: [
    # Desktop clásicas
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/115.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/115.0",
    
    # Móviles avanzados
    "Mozilla/5.0 (Linux; Android 13; Pixel 8 Pro) AppleWebKit/537.36 Chrome/115.0 Mobile",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Safari/605.1.15",
    
    # Técnicas camaleónicas inéditas
    # User-Agent dinámico con fingerprint quirúrgico de navegador real
    "PHORUS-ASCENSION/CAMALEON",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    
    # User-Agent “mezcla de capas” (Chrome + Safari + custom token)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/115.0 Safari/605.1 PHORUS-CAMO/1.0",
    
    # Fingerprint móvil híbrido (Android + Safari Webkit)
    "Mozilla/5.0 (Linux; Android 13; SM-G998U) AppleWebKit/605.1.15 (KHTML, like Gecko) Chrome/115.0 Mobile Safari/605.1 PHORUS-CAMO/ULTRA",
    
    # Técnicas “invisible camaleón”:
    #  - Cambia ligeramente los tokens, version numbers y Webkit strings para evitar detección de fingerprinting
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.1.2 Safari/537.36 PHORUS-X",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1 PHORUS-X",
    "Mozilla/5.0 (Linux; Android 13; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0 Mobile Safari/537.36 PHORUS-X"
])

    fetch_mode: FetchMode = FetchMode.CAMALEON
    allow_redirects: bool = True
    enable_logging: bool = True
    entropy_threshold: float = 3.5  # nivel avanzado para detección

CFG = AscensionConfig()

# ---------------- LOGGING FORENSE ----------------
logger = logging.getLogger("PHORUS_CAM_INV")
logger.setLevel(logging.DEBUG)
handler = logging.FileHandler("phorus_camaleonico.log", encoding="utf-8")
handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
logger.addHandler(handler)

# ---------------- MODELOS ----------------
@dataclass
class Signal:
    score: int
    reasons: List[str]

@dataclass
class Report:
    url: str
    timestamp: str
    score: int
    verdict: str
    confidence: float
    reasons: List[str]
    context: Dict
    mode: str

# ---------------- UTILIDADES ----------------
def now() -> str:
    return datetime.datetime.utcnow().isoformat() + "Z"

def clamp(n: int, lo=0, hi=100) -> int:
    return max(lo, min(hi, n))

def safe(fn, default):
    try:
        return fn()
    except Exception as e:
        logger.warning(str(e))
        return default

def random_user_agent() -> str:
    return random.choice(CFG.user_agents)

# ---------------- HEURÍSTICAS INÉDITAS ----------------
def entropy(s: str) -> float:
    if not s:
        return 0

    # Entropía Shannon clásica (base)
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    base_entropy = -sum(p * math.log2(p) for p in prob)

    # 🔬 Capa inédita: penalización por patrones repetitivos
    repeats = sum(1 for c in set(s) if s.count(c) > len(s) * 0.25)
    pattern_penalty = repeats * 0.15

    # 🔬 Capa inédita: longitud anómala (dominios excesivamente largos)
    length_penalty = 0.2 if len(s) > 25 else 0

    return base_entropy + pattern_penalty + length_penalty


def url_heuristics(url: str) -> Signal:
    p = urlparse(url)
    score, reasons = 0, []

    # ---------------- ENTROPÍA DOMINIO ----------------
    e = entropy(p.netloc)
    if e > CFG.entropy_threshold:
        score += 18
        reasons.append(f"Alta entropía dominio ({e:.2f})")

    # 🔬 NUEVO: entropía del path (tokens ofuscados)
    e_path = entropy(p.path)
    if e_path > CFG.entropy_threshold + 0.4:
        score += 8
        reasons.append("Path con entropía anómala")

    # ---------------- HOMÓGRAFOS / IDN ----------------
    if re.search(r"xn--|[а-яА-Я]", p.netloc):
        score += 22
        reasons.append("Dominio homógrafo / IDN detectado")

    # 🔬 NUEVO: mezcla sospechosa de alfabetos
    if re.search(r"[a-zA-Z]", p.netloc) and re.search(r"\d", p.netloc):
        if sum(c.isdigit() for c in p.netloc) >= 4:
            score += 6
            reasons.append("Dominio alfanumérico camuflado")

    # ---------------- CREDENCIALES EMBEBIDAS ----------------
    if p.username or p.password:
        score += 12
        reasons.append("Credenciales embebidas en URL")

    # ---------------- KEYWORDS SENSIBLES ----------------
    sensitive = r"(login|verify|secure|update|auth|account|password)"
    if re.search(sensitive, p.path.lower()):
        score += 7
        reasons.append("Ruta sensible detectada")

    # 🔬 NUEVO: combinación keyword + query
    if re.search(sensitive, p.query.lower()):
        score += 6
        reasons.append("Keyword sensible en query string")

    # ---------------- PUERTOS ANÓMALOS ----------------
    if p.port and p.port not in (80, 443):
        score += 5
        reasons.append(f"Puerto inusual detectado ({p.port})")

    # ---------------- SUBDOMINIOS PROFUNDOS ----------------
    subdomain_depth = p.netloc.count(".")
    if subdomain_depth >= 4:
        score += 7
        reasons.append("Exceso de subdominios")

    # 🔬 NUEVO: subdominio con keyword sensible
    if re.search(sensitive, p.netloc.lower()):
        score += 9
        reasons.append("Keyword sensible en subdominio")

    return Signal(score, reasons)


SENSITIVE_INPUT_KEYWORDS = (
    # --- Credenciales clásicas ---
    "password", "pass", "passwd", "pwd",
    "login", "signin",

    # --- Autenticación / verificación ---
    "token", "access_token", "auth", "authorization",
    "otp", "totp", "2fa", "mfa", "pin", "code", "verify",

    # --- Identidad personal ---
    "ssn", "dni", "document", "documento",
    "id", "userid", "username", "user",

    # --- Información financiera ---
    "credit", "card", "cc", "ccnum",
    "debit", "iban", "swift", "cvv", "cvc",
    "bank", "account", "routing",

    # --- Contacto sensible ---
    "email", "mail",
    "phone", "tel", "mobile",

    # --- Recuperación / control ---
    "reset", "recovery", "backup", "secret", "answer"
)


JS_COLLECTION_PATTERNS = re.compile(
    r"("
    r"fetch|xmlhttprequest|beacon|sendBeacon|axios|ajax|"
    r"navigator\.|window\.navigator|"
    r"localstorage|sessionstorage|indexeddb|"
    r"document\.cookie|"
    r"postmessage|"
    r"websocket|socket\.io|"
    r"formdata|"
    r"atob|btoa"
    r")",
    re.I
)


PHISHING_TITLE_KEYWORDS = re.compile(
    r"("
    r"login|log in|signin|sign in|"
    r"verify|verification|validated?|"
    r"account|profile|wallet|"
    r"security|secure|suspicious|"
    r"update|upgrade|"
    r"confirm|confirmation|"
    r"reset|recover|restore|"
    r"alert|warning|important"
    r")",
    re.I
)


def _normalize_domain(d: str) -> str:
    if not d:
        return ""
    d = d.lower().strip()
    d = d.lstrip("www.")
    return d


def _is_external(url: str, domain: str) -> bool:
    try:
        netloc = _normalize_domain(urlparse(url).netloc)
        if not netloc:
            return False
        return netloc not in _normalize_domain(domain)
    except Exception:
        return False


def html_heuristics(html: str, domain: str) -> Signal:
    soup = BeautifulSoup(html or "", "html.parser")
    score = 0
    reasons = set()
    domain = _normalize_domain(domain)

    # ================= FORMULARIOS =================
    for f in soup.find_all("form"):
        action = (f.get("action") or "").strip().lower()
        method = (f.get("method") or "get").lower()

        # Form action externo
        if action and _is_external(action, domain):
            score += 15
            reasons.add("Formulario con action externo")

        # Formulario sin action (post fantasma)
        if not action:
            score += 6
            reasons.add("Formulario sin action definido")

        # Método POST con inputs sensibles
        if method == "post":
            for inp in f.find_all("input"):
                name = (inp.get("name") or "").lower()
                if any(k in name for k in SENSITIVE_INPUT_KEYWORDS):
                    score += 8
                    reasons.add("Formulario POST con inputs sensibles")
                    break

        # Formulario oculto (CSS real)
        style = (f.get("style") or "").replace(" ", "").lower()
        if any(x in style for x in ("display:none", "visibility:hidden", "opacity:0")):
            score += 7
            reasons.add("Formulario oculto por CSS")

    # ================= INPUTS =================
    for inp in soup.find_all("input"):
        t = (inp.get("type") or "").lower()
        name = (inp.get("name") or "").lower()

        if t == "password":
            score += 12
            reasons.add("Campo password detectado")

        if any(k in name for k in SENSITIVE_INPUT_KEYWORDS):
            score += 6
            reasons.add("Input con nombre sensible")

        if inp.get("autocomplete") == "off":
            score += 2
            reasons.add("Autocomplete deshabilitado en input")

    # ================= SCRIPTS =================
    for s in soup.find_all("script"):
        src = (s.get("src") or "").lower()
        content = (s.string or "").lower()

        # Script externo
        if src and _is_external(src, domain):
            score += 10
            reasons.add("Script externo detectado")

        # Script inline anormalmente largo
        if not src and len(content) > 1000:
            score += 6
            reasons.add("Script inline extenso")

        # Patrones de recolección / exfiltración
        if JS_COLLECTION_PATTERNS.search(content):
            score += 5
            reasons.add("Script con patrón de recolección de datos")

    # ================= IFRAMES =================
    for i in soup.find_all("iframe"):
        src = (i.get("src") or "").lower()

        if src and _is_external(src, domain):
            score += 8
            reasons.add("Iframe externo detectado")

        if i.get("sandbox") is None:
            score += 3
            reasons.add("Iframe sin sandbox")

        if i.get("width") == "0" or i.get("height") == "0":
            score += 6
            reasons.add("Iframe invisible detectado")

    # ================= ENLACES =================
    external_links = 0
    for a in soup.find_all("a", href=True):
        href = a["href"].lower()
        if href.startswith("http") and _is_external(href, domain):
            external_links += 1

        # Texto vs destino (ingeniería social)
        if a.text and href.startswith("http"):
            if domain in a.text.lower() and _is_external(href, domain):
                score += 5
                reasons.add("Enlace con texto engañoso")

    if external_links >= 6:
        score += 6
        reasons.add("Exceso de enlaces externos")

    # ================= META / CAMUFLAJE =================
    if soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)}):
        score += 8
        reasons.add("Redirección meta-refresh detectada")

    title = (soup.title.string or "").lower() if soup.title else ""
    if PHISHING_TITLE_KEYWORDS.search(title) and domain not in title:
        score += 6
        reasons.add("Título con ingeniería social")

    # ================= RESULTADO =================
    return Signal(score=score, reasons=sorted(reasons))

def enrich_environment_from_html(
    env: EnvironmentProfile,
    html: str,
    domain: str
) -> EnvironmentProfile:
    """
    Enriquece el EnvironmentProfile con información REAL del DOM.
    No altera heurísticas, solo contexto operativo.
    """
    soup = BeautifulSoup(html or "", "html.parser")

    # -------- Formularios reales --------
    forms = soup.find_all("form")
    if forms:
        env.forms_detected = True
        for f in forms:
            action = (f.get("action") or "").lower()
            if action and _is_external(action, domain):
                env.external_calls += 1

    # -------- JS pesado --------
    inline_js_size = 0
    external_scripts = 0

    for s in soup.find_all("script"):
        if s.get("src"):
            external_scripts += 1
        else:
            inline_js_size += len(s.string or "")

    if external_scripts >= 3 or inline_js_size > 3000:
        env.js_heavy = True

    # -------- Ajuste contextual de riesgo --------
    if env.forms_detected and env.js_heavy:
        env.risk_score += 10
        env.suspicious_signals += 1

    return env


# ---------------- COLECTORES CAMALEÓN ----------------
def collect_tls(domain: str) -> Dict:
    def _run():
        if not domain:
            return {}

        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(CFG.tls_timeout)
            s.connect((domain, 443))

            cert = s.getpeercert()

            # Normalización defensiva
            issuer = cert.get("issuer")
            expires = cert.get("notAfter")

            return {
                "issuer": issuer,
                "expires": expires,
                # ---- CAPA FORENSE PASIVA (NO INTRUSIVA) ----
                "subject": cert.get("subject"),
                "serial": cert.get("serialNumber"),
                "version": cert.get("version"),
                "signature_algo": cert.get("signatureAlgorithm"),
            }

    return safe(_run, {})

def http_get(url: str):
    for i in range(CFG.max_retries + 1):
        headers = {
            "User-Agent": random_user_agent(),
            "Accept": "*/*",
            "Connection": "close"
        }

        try:
            r = requests.get(
                url,
                headers=headers,
                timeout=CFG.http_timeout,
                allow_redirects=CFG.allow_redirects
            )

            # ---- CONTROL DE ESTADO (NO INTRUSIVO) ----
            if r.status_code >= 500:
                logger.warning(f"Server error {r.status_code} on {url}")
                time.sleep(0.3)
                continue

            return r

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout retry {i} for {url}")
        except requests.exceptions.ConnectionError as e:
            logger.warning(f"Connection error retry {i} for {url}: {e}")
        except Exception as e:
            logger.warning(f"Retry {i} for {url}: {e}")

        time.sleep(0.3)

    raise RuntimeError("HTTP GET failed")

def build_environment_profile(url: str) -> EnvironmentProfile:
    """
    Perfil inicial del entorno SIN interactuar agresivamente.
    """
    sig_url = url_heuristics(url)

    return EnvironmentProfile(
        risk_score=sig_url.score,
        suspicious_signals=len(sig_url.reasons),
        external_calls=0,
        js_heavy=False,
        forms_detected=False
    )

def resolve_mode_for_url(url: str) -> FetchMode:
    env = build_environment_profile(url)
    return resolve_fetch_mode(CFG.fetch_mode, env)


def extract_relevant_html(html: str, max_kb: int) -> str:
    """
    Extrae partes relevantes del HTML priorizando head, forms y scripts.
    Mantiene límites defensivos de tamaño.
    """
    if not html:
        return ""

    limit = max_kb * 1024

    head_end = html.lower().find("</head>")
    head = html[:head_end + 7] if head_end != -1 else html[:limit // 3]

    tail = html[-limit // 2:]

    combined = head + "\n<!-- TRUNCATED -->\n" + tail
    return combined[:limit]


# ---------------- MOTOR FORENSE ----------------
def analyze(url: str) -> Report:

    signals: List[Signal] = []
    context: Dict = {}

    # ================= PRE-ANÁLISIS =================
    sig_url = url_heuristics(url)
    signals.append(sig_url)

    # Resolver modo real (camaleón)
    resolved_mode = resolve_mode_for_url(url)
    context["resolved_mode"] = resolved_mode.value

    # ================= FETCH CONTROLADO =================
    r = None
    if resolved_mode != FetchMode.PASSIVE:
        r = safe(lambda: http_get(url), None)

    sig_html: Signal | None = None
    if r:
        domain = urlparse(url).netloc

        html = extract_relevant_html(r.text, CFG.max_html_kb)
        sig_html = html_heuristics(html, domain)
        signals.append(sig_html)

        # 🔹 Enriquecimiento contextual (NO altera score ni modo)
        env = build_environment_profile(url)
        env = enrich_environment_from_html(env, html, domain)

        context["environment"] = {
            "js_heavy": env.js_heavy,
            "forms_detected": env.forms_detected,
            "external_calls": env.external_calls,
        }

        context["status"] = r.status_code
        context["tls"] = collect_tls(domain)

    # ================= AGREGACIÓN CORREGIDA =================
    url_score = sig_url.score
    html_score = sig_html.score if sig_html else 0

    # Caps defensivos por dominio semántico
    url_score = min(url_score, 40)
    html_score = min(html_score, 50)

    total = url_score + html_score

    # ================= VEREDICTO (CENTRALIZADO) =================
    med, high = verdict_thresholds(resolved_mode)

    verdict = (
        "ALTO RIESGO" if total >= high else
        "RIESGO MEDIO" if total >= med else
        "BAJO RIESGO"
    )

    # ================= CONFIDENCE NO LINEAL (EVIDENCIA-AWARE) =================
    k = 0.085
    midpoint = 45

    base_confidence = 1 / (1 + math.exp(-k * (total - midpoint)))

    signal_count = sum(len(s.reasons) for s in signals)
    signal_factor = min(1.0, signal_count / 12)

    confidence = (
        base_confidence * 0.85 +
        signal_factor * 0.15
    )

    confidence = round(min(0.99, max(0.25, confidence)), 2)

    # ================= RAZONES =================
    reasons = []
    for s in signals:
        reasons.extend(s.reasons)

    return Report(
        url=url,
        timestamp=now(),
        score=clamp(total),
        verdict=verdict,
        confidence=confidence,
        reasons=reasons,
        context=context,
        mode=resolved_mode.value
    )



# ---------------- CLI NEÓN CAMALEÓN INVISIBLE ----------------
def cli():
    try:
        console = Console()
    except Exception:
        print("Error inicializando consola avanzada.")
        return

    # ─────────────────────────────────────────
    # ✨ Escritura animada línea por línea (neón)
    # ─────────────────────────────────────────
    def neon_lines(
        text: str,
        delay: float = 0.35,
        style: str = "bold magenta",
        glow: bool = True,
    ):
        """
        Imprime texto línea por línea como si el sistema escribiera solo.
        Elegante, lento, seguro, futurista.
        """
        if not text:
            return

        for line in text.splitlines():
            try:
                render = Text(line, style=style)
                if glow:
                    render.stylize("bold")
                console.print(render)
                time.sleep(delay)
            except Exception:
                # fallback silencioso, sin romper UX
                print(line)
                time.sleep(delay)

    # ─────────────────────────────────────────
    # 🌌 Intro del futuro (cristalino)
    # ─────────────────────────────────────────
    console.clear()

    neon_lines(
        "PHORUS ASCENSION ∞ — CAMALEÓN EDITION",
        delay=0.45,
        style="bold magenta",
    )

    neon_lines(
        "╭────────────────────────────────────────────╮\n"
        "│ El futuro no se ataca.                     │\n"
        "│ El futuro se observa.                      │\n"
        "│ Se analiza. Se comprende.                  │\n"
        "│                                            │\n"
        "│ Bienvenido al análisis forense consciente. │\n"
        "╰────────────────────────────────────────────╯",
        delay=0.30,
        style="cyan",
    )

    console.print(
        Panel(
            "[bold cyan]Sistema forense adaptativo iniciado[/bold cyan]\n"
            "[red]Modo:[/] Observación heurística híbrida\n"
            "[red]Autor:[/] ByMakaveli New Era\n"
            "[red]Estado:[/] Estable · Seguro · Defensivo · Silencioso",
            style="bold magenta",
            padding=(1, 2),
        )
    )

    # ─────────────────────────────────────────
    # 🔁 Loop principal (robusto)
    # ─────────────────────────────────────────
    while True:
        try:
            console.print(
                "\n[bold cyan]1)[/] Analizar URL\n"
                "[bold cyan]2)[/] Salir"
            )

            op = console.input("[bold neon_green]> [/]")

            if op.strip() == "1":
                url = console.input("[bold cyan]URL objetivo (https://ejemplo.com): [/]")

                if not url or not isinstance(url, str):
                    console.print(
                        Panel("URL inválida. Entrada vacía.", style="red")
                    )
                    continue

                # Animación de análisis
                for _ in track(
                    range(18),
                    description="[magenta]Camuflaje forense activo[/magenta]",
                ):
                    time.sleep(0.04)

                # Ejecución segura
                try:
                    rep = analyze(url)
                except Exception as e:
                    console.print(
                        Panel(
                            f"Error durante el análisis:\n{e}",
                            title="Fallo controlado",
                            style="red",
                        )
                    )
                    continue

                # Renderizado de resultados
                try:
                    table = Table(
                        title="Resultado Forense",
                        box=box.DOUBLE,
                        style="magenta",
                        show_lines=True,
                    )
                    table.add_column("Campo", style="cyan", no_wrap=True)
                    table.add_column("Valor", style="magenta")

                    if isinstance(rep, dict):
                        for k, v in rep.items():
                            table.add_row(
                                str(k),
                                json.dumps(v, ensure_ascii=False, indent=2)
                                if isinstance(v, (dict, list))
                                else str(v),
                            )
                    else:
                        for k, v in rep.__dict__.items():
                            table.add_row(str(k), str(v))

                    console.print(table)

                except Exception as e:
                    console.print(
                        Panel(
                            f"Error renderizando resultados:\n{e}",
                            style="red",
                        )
                    )

            elif op.strip() == "2":
                neon_lines(
                    "Cerrando interfaz forense...\n"
                    "Memoria sincronizada.\n"
                    "Hasta la próxima observación.",
                    delay=0.35,
                    style="bold red",
                )
                break

            else:
                console.print(
                    Panel("Opción no válida. Usa 1 o 2.", style="yellow")
                )

        except KeyboardInterrupt:
            console.print(
                Panel(
                    "Interrupción detectada.\nSalida segura del sistema.",
                    style="bold red",
                )
            )
            break

        except Exception as e:
            console.print(
                Panel(
                    f"Error inesperado controlado:\n{e}",
                    title="Guardrail activo",
                    style="red",
                )
            )



if __name__ == "__main__":
    cli()
