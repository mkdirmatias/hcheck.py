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
    print(f"\n{color}{header}{Style.RESET_ALL}")


class HeaderPriority(Enum):
    CRITICAL = "CRÍTICO"
    HIGH = "ALTA"
    MEDIUM = "MEDIA"
    OPTIONAL = "OPCIONAL"


class HeaderSource:
    def __init__(self):
        self.session = requests.Session()

    #
    # Obtiene los encabezados de una URL
    #
    def get_from_url(
        self,
        url: str,
        proxy: Dict[str, str] = None,
        verify_ssl: bool = True,
    ) -> Dict[str, str]:
        try:
            if proxy:
                self.session.proxies.update(proxy)

            response = self.session.get(url, verify=verify_ssl)
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
        implementation = "Obligatoria" if config["required"] else "Opcional"

        # Resumir el output o mostrarlo detallado
        if not resume:
            output = [
                f" \n✅ {Fore.CYAN}{Style.BRIGHT}{header}:{Style.RESET_ALL}",
                f"   - Descripción: {config['description']}",
                f"   - Valor obtenido: {current_value}",
                f"   - Implementación: {implementation}",
                f"   - Estado: Implementado",
            ]
        else:
            output = [
                f" \n✅ {Fore.CYAN}{Style.BRIGHT}{header}:{Style.RESET_ALL} Valor obtenido: {current_value}",
            ]

        if improvements:
            output.append(
                f"   - {Style.BRIGHT}Recomendación:{Style.RESET_ALL} {'; '.join(improvements)}"
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
        implementation = "Obligatoria" if config["required"] else "Opcional"

        # Resumir el output o mostrarlo detallado
        if not resume:
            output = [
                f" \n❌ {Fore.RED}{Style.BRIGHT}{header}:{Style.RESET_ALL}",
                f"   - Descripción: {config['description']}",
                f"   - Implementación: {implementation}",
                f"   - Valor recomendado: {config['recommended_value']}",
                f"   - Estado: Faltante",
            ]
        else:
            output = [
                f" \n❌ {Fore.RED}{Style.BRIGHT}{header}:{Style.RESET_ALL} Valor recomendado: {config['recommended_value']}",
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
        help="URL para analizar los encabezados",
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

    args = parser.parse_args()

    try:
        header_source = HeaderSource()
        analyzer = SecurityHeaderAnalyzer()

        # Configurar proxy si se proporciona
        proxy = None
        if args.proxy:
            proxy = {"http": args.proxy, "https": args.proxy}

        # Obtener encabezados según la fuente
        if args.url:
            print(f"{Fore.CYAN}Obteniendo encabezados de: {args.url}{Style.RESET_ALL}")
            headers = header_source.get_from_url(args.url, proxy, not args.no_verify)
        else:
            if args.host:
                print(f"{Fore.CYAN}Leyendo encabezados de {args.host}{Style.RESET_ALL}")
            else:
                print(
                    f"{Fore.CYAN}Leyendo encabezados del archivo: {args.file}{Style.RESET_ALL}"
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
        }

        # Primero mostrar todos los headers presentes si se ha seleccionado resumen
        if args.resume:
            for priority in HeaderPriority:
                for header in results[priority]["present"]:
                    print(f"  {header}")

            for priority in HeaderPriority:
                for header in results[priority]["missing"]:
                    print(f"  {header}")
        else:
            for priority in HeaderPriority:
                print_section_header(priority.value, priority_colors[priority])

                if results[priority]["present"]:
                    for header in results[priority]["present"]:
                        print(f"  {header}")

                if results[priority]["missing"]:
                    for header in results[priority]["missing"]:
                        print(f"  {header}")

    except Exception as e:
        print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        parser.print_help()


if __name__ == "__main__":
    main()
