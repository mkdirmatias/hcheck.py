#!/usr/bin/env python3
import textwrap
import requests
import argparse
from typing import Dict, List, Tuple
from colorama import init, Fore, Style
from enum import Enum
from urllib3.exceptions import InsecureRequestWarning

# Suprimir advertencias de verificación SSL
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


BANNER = """
██   ██  ██████ ██   ██ ███████  ██████ ██   ██
██   ██ ██      ██   ██ ██      ██      ██  ██
███████ ██      ███████ █████   ██      █████
██   ██ ██      ██   ██ ██      ██      ██  ██
██   ██  ██████ ██   ██ ███████  ██████ ██   ██   v1.0
                                        
        HTTP Security Headers Checker
              by @unkndown
=================================================
"""


#
# Imprime el banner con colores.
#
def print_banner():
    print(f"{Fore.CYAN}{BANNER}{Style.RESET_ALL}")


# Definir las descripciones de cada sección
SECTION_DESCRIPTIONS = {
    "CRÍTICO": "Headers que son realmente necesarios para la seguridad del aplicativo. Su ausencia representa un riesgo significativo.",
    "ALTA": "Headers importantes que proporcionan capas adicionales de seguridad. Se recomienda fuertemente su implementación.",
    "MEDIA": "Headers que mejoran la seguridad pero son específicos para ciertos casos de uso o proporcionan protección adicional.",
    "OPCIONAL": "Headers que pueden ser necesarios según el contexto específico del aplicativo, especialmente para configuraciones CORS.",
    "EXPOSICIÓN": "Headers que exponen información sensible sobre tecnologías, versiones o configuraciones del servidor. Se recomienda ocultarlos o eliminarlos.",
}

SECTION_TEMPLATE = """
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃        Encabezados {priority:^12}      ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
{description}
"""


#
# Ajusta el texto a un ancho específico y lo centra
#
def wrap_description(
    text: str,
    width: int = 45,
) -> str:
    wrapped_lines = textwrap.wrap(text, width=width)
    return "\n".join(wrapped_lines)


#
# Imprime el encabezado de sección con el diseño seleccionado.
#
def print_section_header(priority: str, color: str) -> None:
    description = SECTION_DESCRIPTIONS.get(priority, "")
    wrapped_description = wrap_description(description)
    header = SECTION_TEMPLATE.format(priority=priority, description=wrapped_description)
    print(f"{color}{header}{Style.RESET_ALL}")


class HeaderPriority(Enum):
    CRITICAL = "CRÍTICO"
    HIGH = "ALTA"
    MEDIUM = "MEDIA"
    OPTIONAL = "OPCIONAL"
    DISCLOSURE = "EXPOSICIÓN"


class HeaderSource:
    def __init__(self):
        self.session = requests.Session()

    #
    # Obtiene los encabezados de una URL
    #
    def get_from_url(
        self,
        url: str,
        custom_headers: Dict[str, str] = None,
        proxy: Dict[str, str] = None,
        verify_ssl: bool = True,
    ) -> Dict[str, str]:
        try:
            if proxy:
                self.session.proxies.update(proxy)

            headers = {}
            if custom_headers:
                headers.update(custom_headers)

            response = self.session.get(url, headers=headers, verify=verify_ssl)
            return dict(response.headers)
        except requests.exceptions.RequestException as e:
            raise Exception(f"Error al obtener los encabezados de la URL: {str(e)}")

    #
    # Obtiene los encabezados de un archivo
    #
    def get_from_file(
        self,
        file_path: str,
    ) -> Dict[str, str]:
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                content = file.read()

            headers = {}
            for line in content.split("\n"):
                if ": " in line:
                    key, value = line.split(": ", 1)
                    headers[key.strip()] = value.strip()
            return headers
        except Exception as e:
            raise Exception(f"Error al leer el archivo: {str(e)}")


class SecurityHeaderAnalyzer:
    def __init__(self):
        init()
        self.recommended_headers = {
            # CRÍTICOS - Estos son realmente obligatorios
            "Content-Security-Policy": {
                "priority": HeaderPriority.CRITICAL,
                "required": True,
                "recommended_value": "default-src 'self'; script-src 'self' trusted-scripts.com; img-src *",
                "description": "Define fuentes permitidas para cargar recursos",
            },
            "Strict-Transport-Security": {
                "priority": HeaderPriority.CRITICAL,
                "required": True,
                "recommended_value": "max-age=31536000; includeSubDomains; preload",
                "description": "Fuerza conexiones HTTPS",
            },
            "X-Content-Type-Options": {
                "priority": HeaderPriority.CRITICAL,
                "required": True,
                "recommended_value": "nosniff",
                "description": "Previene MIME-type sniffing",
            },
            "X-Frame-Options": {
                "priority": HeaderPriority.CRITICAL,
                "required": True,
                "recommended_value": "DENY",
                "description": "Previene clickjacking",
            },
            # ALTA PRIORIDAD - Importantes pero no siempre obligatorios
            "Permissions-Policy": {
                "priority": HeaderPriority.HIGH,
                "required": False,
                "recommended_value": "geolocation=(), camera=(), microphone=(), payment=()",
                "description": "Controla características del navegador permitidas",
            },
            "Referrer-Policy": {
                "priority": HeaderPriority.HIGH,
                "required": False,
                "recommended_value": "strict-origin-when-cross-origin",
                "description": "Controla información del Referrer",
            },
            "Cross-Origin-Opener-Policy": {
                "priority": HeaderPriority.HIGH,
                "required": False,
                "recommended_value": "same-origin",
                "description": "Aísla el navegador de ventanas cross-origin",
            },
            "Cross-Origin-Resource-Policy": {
                "priority": HeaderPriority.HIGH,
                "required": False,
                "recommended_value": "same-origin",
                "description": "Protege recursos de ser cargados cross-origin",
            },
            # MEDIA PRIORIDAD - Opcionales según el contexto
            "X-XSS-Protection": {
                "priority": HeaderPriority.MEDIUM,
                "required": False,
                "recommended_value": "1; mode=block",
                "description": "Protección adicional contra XSS (para navegadores antiguos)",
            },
            "Clear-Site-Data": {
                "priority": HeaderPriority.MEDIUM,
                "required": False,
                "recommended_value": '"cache","cookies","storage"',
                "description": "Limpia datos del navegador al cerrar sesión",
            },
            "Cross-Origin-Embedder-Policy": {
                "priority": HeaderPriority.MEDIUM,
                "required": False,
                "recommended_value": "require-corp",
                "description": "Asegura que los recursos cross-origin estén opt-in",
            },
            "Expect-CT": {
                "priority": HeaderPriority.HIGH,  # o MEDIUM según consideremos
                "required": False,
                "recommended_value": "max-age=86400, enforce",
                "description": "Certificate Transparency enforcement",
            },
            "X-Permitted-Cross-Domain-Policies": {
                "priority": HeaderPriority.MEDIUM,
                "required": False,
                "recommended_value": "none",
                "description": "Controla políticas cross-domain para archivos Adobe",
            },
            # OPCIONALES - Necesarios solo si se usa CORS
            "Access-Control-Allow-Origin": {
                "priority": HeaderPriority.OPTIONAL,
                "required": False,
                "recommended_value": "https://dominio.com",
                "description": "Control de CORS - orígenes permitidos",
            },
            "Access-Control-Allow-Methods": {
                "priority": HeaderPriority.OPTIONAL,
                "required": False,
                "recommended_value": "GET, POST, OPTIONS",
                "description": "Control de CORS - métodos permitidos",
            },
            "Access-Control-Allow-Headers": {
                "priority": HeaderPriority.OPTIONAL,
                "required": False,
                "recommended_value": "Content-Type, Authorization",
                "description": "Control de CORS - cabeceras permitidas",
            },
            "Access-Control-Max-Age": {
                "priority": HeaderPriority.OPTIONAL,
                "required": False,
                "recommended_value": "86400",
                "description": "Control de CORS - tiempo de cache para preflight",
            },
            # HEADERS DE EXPOSICIÓN
            "Server": {
                "priority": HeaderPriority.DISCLOSURE,
                "required": False,
                "recommended_value": "",
                "description": "Expone información del servidor web",
            },
            "X-Powered-By": {
                "priority": HeaderPriority.DISCLOSURE,
                "required": False,
                "recommended_value": "",
                "description": "Expone información sobre el framework/lenguaje utilizado",
            },
            "X-AspNet-Version": {
                "priority": HeaderPriority.DISCLOSURE,
                "required": False,
                "recommended_value": "",
                "description": "Expone la versión de ASP.NET",
            },
            "X-AspNetMvc-Version": {
                "priority": HeaderPriority.DISCLOSURE,
                "required": False,
                "recommended_value": "",
                "description": "Expone la versión de ASP.NET MVC",
            },
            "X-Runtime": {
                "priority": HeaderPriority.DISCLOSURE,
                "required": False,
                "recommended_value": "",
                "description": "Expone información sobre el runtime (común en Ruby)",
            },
            "X-Generator": {
                "priority": HeaderPriority.DISCLOSURE,
                "required": False,
                "recommended_value": "",
                "description": "Expone información sobre el generador del sitio",
            },
            "X-Drupal-Cache": {
                "priority": HeaderPriority.DISCLOSURE,
                "required": False,
                "recommended_value": "",
                "description": "Expone información de Drupal",
            },
            "X-Varnish": {
                "priority": HeaderPriority.DISCLOSURE,
                "required": False,
                "recommended_value": "",
                "description": "Expone información del cache Varnish",
            },
            "Via": {
                "priority": HeaderPriority.DISCLOSURE,
                "required": False,
                "recommended_value": "",
                "description": "Expone información sobre proxies/gateways intermedios",
            },
            "X-Served-By": {
                "priority": HeaderPriority.DISCLOSURE,
                "required": False,
                "recommended_value": "",
                "description": "Expone el servidor que procesó la petición",
            },
            "X-Client-IP": {
                "priority": HeaderPriority.DISCLOSURE,
                "required": False,
                "recommended_value": "",
                "description": "Expone la IP del cliente",
            },
            "X-Server-IP": {
                "priority": HeaderPriority.DISCLOSURE,
                "required": False,
                "recommended_value": "",
                "description": "Expone la IP del servidor",
            },
            "X-Backend-Server": {
                "priority": HeaderPriority.DISCLOSURE,
                "required": False,
                "recommended_value": "",
                "description": "Expone información del servidor backend",
            },
        }

    #
    # Formatea la información de un header presente.
    #
    def format_present_header(
        self,
        header: str,
        current_value: str,
        config: dict,
        improvements: List[str],
        resume: bool = False,
    ) -> str:
        if config["required"]:
            implementation = f"{Fore.RED}Obligatorio{Style.RESET_ALL}"
        else:
            implementation = f"{Fore.BLUE}Opcional{Style.RESET_ALL}"

        if config["priority"] == HeaderPriority.DISCLOSURE:
            implementation = f"{Fore.LIGHTRED_EX}Remover{Style.RESET_ALL}"

        # Resumir el output o mostrarlo detallado
        if not resume:
            output = [
                f" \n✅ {Fore.CYAN}{Style.BRIGHT}{header}:{Style.RESET_ALL}",
                f"   - {Style.BRIGHT}Descripción:{Style.RESET_ALL} {config['description']}",
                f"   - {Style.BRIGHT}Valor obtenido:{Style.RESET_ALL} {current_value}",
                f"   - {Style.BRIGHT}Implementación:{Style.RESET_ALL} {implementation}",
                f"   - {Style.BRIGHT}Estado:{Style.RESET_ALL} Implementado",
            ]
        else:
            output = [
                f"[{Fore.GREEN}*{Style.RESET_ALL}] {Fore.CYAN}{Style.BRIGHT}{header} ({implementation}):{Style.RESET_ALL} Valor obtenido: {current_value}",
            ]

        if improvements:
            if not resume:
                output.append(
                    f"   - {Style.BRIGHT}Recomendación:{Style.RESET_ALL} {'; '.join(improvements)}"
                )
            else:
                output.append(
                    f"      - {Style.BRIGHT}Recomendación:{Style.RESET_ALL} {'; '.join(improvements)}"
                )

        return "\n".join(output)

    #
    # Formatea la información de un header faltante.
    #
    def format_missing_header(
        self,
        header: str,
        config: dict,
        resume: bool = False,
    ) -> str:

        if config["required"]:
            implementation = f"{Fore.RED}Obligatorio{Style.RESET_ALL}"
            name = f"{Fore.RED}{Style.BRIGHT}{header}:{Style.RESET_ALL}"
        else:
            implementation = f"{Fore.YELLOW}Opcional{Style.RESET_ALL}"
            name = f"{Fore.YELLOW}{Style.BRIGHT}{header}:{Style.RESET_ALL}"

        # Resumir el output o mostrarlo detallado
        if not resume:
            output = [
                f"\n❌ {name}",
                f"   - {Style.BRIGHT}Descripción:{Style.RESET_ALL} {config['description']}",
                f"   - {Style.BRIGHT}Implementación:{Style.RESET_ALL} {implementation}",
                f"   - {Style.BRIGHT}Valor recomendado:{Style.RESET_ALL} {config['recommended_value']}",
                f"   - {Style.BRIGHT}Estado:{Style.RESET_ALL} Faltante",
            ]
        else:
            output = [
                f"[{Fore.RED}!{Style.RESET_ALL}] {name} ({implementation}):{Style.RESET_ALL} Valor recomendado: {config['recommended_value']}",
            ]

        return "\n".join(output)

    #
    # Analiza los encabezados presentes y genera recomendaciones por prioridad.
    #
    def analyze_headers(
        self,
        headers: Dict[str, str],
        resume: bool = False,
    ) -> Dict[HeaderPriority, Dict[str, List[str]]]:
        results = {
            HeaderPriority.CRITICAL: {"present": [], "missing": []},
            HeaderPriority.HIGH: {"present": [], "missing": []},
            HeaderPriority.MEDIUM: {"present": [], "missing": []},
            HeaderPriority.OPTIONAL: {"present": [], "missing": []},
            HeaderPriority.DISCLOSURE: {"present": [], "missing": []},
        }

        for header, config in self.recommended_headers.items():
            priority = config["priority"]
            header_lower = header.lower()

            # Buscar el encabezado de forma case-insensitive
            header_found = None
            for present_header in headers:
                if present_header.lower() == header_lower:
                    header_found = present_header
                    break

            if not header_found:
                # Solo agregar a missing si NO es un header de exposición
                if priority != HeaderPriority.DISCLOSURE:
                    results[priority]["missing"].append(
                        self.format_missing_header(
                            header,
                            config,
                            resume,
                        )
                    )
            else:
                current_value = headers[header_found]
                improvements = []

                # Analizar mejoras específicas por header
                if header == "Strict-Transport-Security":
                    if "preload" not in current_value.lower():
                        improvements.append("Agregar 'preload' para mayor seguridad")
                    if "includeSubDomains" not in current_value:
                        improvements.append(
                            "Agregar 'includeSubDomains' para proteger subdominios"
                        )

                elif header == "Content-Security-Policy":
                    if current_value == "default-src 'self'":
                        improvements.append(
                            "Considerar una política más específica según necesidades"
                        )

                elif header == "X-Frame-Options":
                    if current_value.upper() not in ["DENY", "SAMEORIGIN"]:
                        improvements.append(
                            "Usar 'DENY' o 'SAMEORIGIN' para mayor seguridad"
                        )

                elif header == "X-XSS-Protection":
                    if current_value != "1; mode=block":
                        improvements.append(
                            "Usar '1; mode=block' para mejor protección"
                        )

                elif header == "Access-Control-Allow-Origin":
                    if current_value == "*":
                        improvements.append(
                            "El valor '*' es inseguro. Especifica los dominios permitidos explícitamente"
                        )

                elif header in [
                    "Server",
                    "X-Powered-By",
                    "X-AspNet-Version",
                    "X-AspNetMvc-Version",
                    "X-Runtime",
                    "X-Generator",
                    "X-Drupal-Cache",
                    "X-Varnish",
                    "Via",
                    "X-Served-By",
                    "X-Client-IP",
                    "X-Server-IP",
                    "X-Backend-Server",
                ]:
                    if current_value and not current_value.strip() == "":
                        improvements.append(
                            f"Se recomienda eliminar o ocultar este header para evitar exponer información sensible"
                        )

                results[priority]["present"].append(
                    self.format_present_header(
                        header,
                        current_value,
                        config,
                        improvements,
                        resume,
                    )
                )

        return results


#
# Imprime una sección con título coloreado
#
def print_colored_section(
    title: str,
    items: List[str],
    color: str,
    indent: str = "",
) -> None:
    if items:
        print(f"\n{indent}{color}{title}{Style.RESET_ALL}")
        for item in items:
            print(f"{indent}{item}")


#
# Decorador para capturar el output de la función
#
def capture_output(func):
    from io import StringIO
    import sys

    def wrapper(*args, **kwargs):
        # Guardar el stdout original
        old_stdout = sys.stdout
        # Crear un buffer para capturar el output
        result = StringIO()
        sys.stdout = result

        try:
            # Ejecutar la función original
            func(*args, **kwargs)
            # Obtener el output capturado
            output = result.getvalue()
            # Restaurar stdout
            sys.stdout = old_stdout
            # Imprimir en pantalla
            print(output, end="")
            return output
        finally:
            sys.stdout = old_stdout
            result.close()

    return wrapper


#
# Analiza y imprime los resultados
#
@capture_output
def analyze_and_print_results(header_source, analyzer, args, proxy):
    # Obtener encabezados según la fuente
    if args.url:
        print(f"{Fore.CYAN}Obteniendo encabezados de: {args.url}{Style.RESET_ALL}\n")

        # Procesar headers personalizados si existen
        custom_headers = {}
        if args.header:
            for header in args.header:
                try:
                    name, value = header.split(":", 1)
                    custom_headers[name.strip()] = value.strip()
                except ValueError:
                    print(
                        f"{Fore.RED}Error: formato de header inválido: {header}{Style.RESET_ALL}"
                    )
                    continue

        headers = header_source.get_from_url(
            args.url,
            custom_headers=custom_headers,
            proxy=proxy,
            verify_ssl=not args.no_verify,
        )
    else:
        if args.host:
            print(f"{Fore.CYAN}Leyendo encabezados de {args.host}{Style.RESET_ALL}\n")
        else:
            print(
                f"{Fore.CYAN}Leyendo encabezados del archivo: {args.file}{Style.RESET_ALL}\n"
            )

        headers = header_source.get_from_file(args.file)

    # Analizar encabezados
    results = analyzer.analyze_headers(headers, args.resume)

    # Imprimir resultados por prioridad
    priority_colors = {
        HeaderPriority.CRITICAL: Fore.MAGENTA,
        HeaderPriority.HIGH: Fore.YELLOW,
        HeaderPriority.MEDIUM: Fore.GREEN,
        HeaderPriority.OPTIONAL: Fore.BLUE,
        HeaderPriority.DISCLOSURE: Fore.LIGHTRED_EX,
    }

    # Primero mostrar todos los headers presentes si se ha seleccionado --resume
    if args.resume:
        for priority in HeaderPriority:
            for header in results[priority]["present"]:
                print(f"  {header}")

        for priority in HeaderPriority:
            for header in results[priority]["missing"]:
                print(f"  {header}")
    else:
        for priority in HeaderPriority:
            # Solo mostrar la sección DISCLOSURE si hay headers presentes
            if (
                priority == HeaderPriority.DISCLOSURE
                and not results[priority]["present"]
            ):
                continue

            if not args.resume:
                print_section_header(priority.value, priority_colors[priority])

            if results[priority]["present"]:
                for header in results[priority]["present"]:
                    print(f"  {header}")

            if results[priority]["missing"] and priority != HeaderPriority.DISCLOSURE:
                for header in results[priority]["missing"]:
                    print(f"  {header}")


#
# Analiza múltiples URLs y retorna sus resultados
#
@capture_output
def analyze_multiple_urls(header_source, analyzer, urls, args, proxy):
    for url in urls:
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Analizando: {url}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n")

        try:
            # Guardamos la URL original
            original_url = args.url
            # Asignamos la URL actual
            args.url = url

            # Usamos la función existente
            analyze_and_print_results(header_source, analyzer, args, proxy)

            # Restauramos la URL original
            args.url = original_url

        except Exception as e:
            print(f"{Fore.RED}Error analizando {url}: {str(e)}{Style.RESET_ALL}")


#
# Imprime el resumen de resultados
#
def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="Analizador de Encabezados de Seguridad HTTP"
    )

    source_group = parser.add_mutually_exclusive_group(required=True)

    source_group.add_argument(
        "--url",
        action="append",
        help="URL para analizar. Se puede usar múltiples veces",
    )

    source_group.add_argument(
        "--urls-file",
        help="Archivo con lista de URLs para analizar (una por línea)",
    )

    source_group.add_argument(
        "--file",
        help="Archivo con los encabezados para analizar",
    )

    parser.add_argument(
        "--host",
        help="URL a mostrar en el output",
    )

    parser.add_argument(
        "--resume",
        action="store_true",
        help="Output resumido",
    )

    parser.add_argument(
        "--proxy", help="Proxy para usar (formato: http://user:pass@host:port)"
    )

    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Deshabilitar verificación SSL cuando se usa una URL",
    )

    parser.add_argument(
        "--header",
        action="append",
        help="Headers personalizados (formato: 'Nombre:Valor'). Se puede usar múltiples veces",
    )

    parser.add_argument(
        "--output",
        help="Archivo de salida para guardar los resultados (ejemplo: resultados.txt)",
    )

    args = parser.parse_args()

    try:
        header_source = HeaderSource()
        analyzer = SecurityHeaderAnalyzer()

        # Configurar proxy si se proporciona
        proxy = None
        if args.proxy:
            proxy = {"http": args.proxy, "https": args.proxy}

        if args.urls_file:
            # Leer URLs del archivo
            try:
                with open(args.urls_file, "r") as f:
                    urls = [line.strip() for line in f if line.strip()]
            except Exception as e:
                print(
                    f"{Fore.RED}Error leyendo archivo de URLs: {str(e)}{Style.RESET_ALL}"
                )
                return

            output = analyze_multiple_urls(header_source, analyzer, urls, args, proxy)

        elif args.url:
            # URLs proporcionadas por línea de comando
            output = analyze_multiple_urls(
                header_source, analyzer, args.url, args, proxy
            )

        else:
            # Análisis de archivo de headers
            output = analyze_and_print_results(header_source, analyzer, args, proxy)

        # Si se especificó un archivo de salida, guardar los resultados
        if args.output:
            try:
                with open(args.output, "w", encoding="utf-8") as f:
                    import re

                    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
                    clean_output = ansi_escape.sub("", output)
                    f.write(clean_output)
                print(
                    f"\n{Fore.GREEN}Resultados guardados en: {args.output}{Style.RESET_ALL}"
                )
            except Exception as e:
                print(
                    f"\n{Fore.RED}Error al guardar el archivo: {str(e)}{Style.RESET_ALL}"
                )

    except Exception as e:
        print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        parser.print_help()


if __name__ == "__main__":
    main()
