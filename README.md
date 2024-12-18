<p align="center">
  <img src="https://i.imgur.com/k27uAdr.png" alt="HCheck" width="400">
</p>

# HCheck - HTTP Security Headers Checker

`hcheck.py` es una herramienta de línea de comandos que analiza los headers de seguridad HTTP, ya sea de una URL o de un archivo local. La herramienta evalúa la presencia y configuración de headers de seguridad críticos y proporciona recomendaciones para mejorar la seguridad.

## Características

- Análisis de headers de seguridad HTTP
- Soporte para análisis de URLs y archivos locales
- Soporte para múltiples URLs
- Guardar output en archivo de texto
- Categorización de headers por categoría (Crítico, Alta, Media, Opcional, Exposición)
- Verificación de configuraciones recomendadas
- Soporte para proxy
- Soporte para encabezados HTTP personalizados
- Modo resumen para salida compacta
- Recuento de encabezados faltantes y presentes
- Códigos de colores para mejor legibilidad

## Instalación

1. Clona el repositorio:
```bash
git clone https://github.com/unkndown/hcheck.git
```

2. Instala las dependencias:
```bash
pip install -r requirements.txt
```

## Uso

### Análisis de una URL:
```bash
python3 hcheck.py --url https://ejemplo.com
```

### Análisis de un archivo local:
```bash
python3 hcheck.py --file headers.txt
```

### Usar con proxy:
```bash
python3 hcheck.py --url https://ejemplo.com --proxy http://127.0.0.1:8080
```

### Modo resumen:
```bash
python3 hcheck.py --url https://ejemplo.com --resume
```

### Headers personalizados:
```bash
python script.py --url https://ejemplo.com --header "Cookie:sessionId=123" --header "Authorization:Bearer token123"
```

### Guardar resultados en archivo:
```bash
python3 hcheck.py --url https://ejemplo.com --output resultados.txt
```

### Análisis de múltiples URLs:
```bash
# Usando múltiples --url
python3 hcheck.py --url https://ejemplo1.com --url https://ejemplo2.com

# Usando un archivo con URLs
python3 hcheck.py --urls-file lista_urls.txt
```

### Opciones disponibles:
```
opciones:
  -h, --help           Muestra este mensaje de ayuda
  --url URL            URL para analizar. Se puede usar múltiples veces
  --urls-file FILE     Archivo con lista de URLs para analizar (una por línea)
  --file FILE          Archivo con los encabezados para analizar
  --host HOST          URL a mostrar en el output
  --resume             Output resumido
  --proxy PROXY        Proxy para usar (formato: http://user:pass@host:port)
  --no-verify          Deshabilitar verificación SSL cuando se usa una URL
  --header HEADER      Headers personalizados (formato: 'Nombre:Valor'). Se puede usar múltiples veces
  --output OUTPUT      Archivo de salida para guardar los resultados (ejemplo: resultados.txt)
```

## Headers Analizados

### Críticos
- Content-Security-Policy
- Strict-Transport-Security
- X-Content-Type-Options
- X-Frame-Options

### Alta Prioridad
- Permissions-Policy
- Referrer-Policy
- Cross-Origin-Opener-Policy
- Cross-Origin-Resource-Policy

### Media Prioridad
- X-XSS-Protection
- Clear-Site-Data
- Cross-Origin-Embedder-Policy

### Opcionales (CORS)
- Access-Control-Allow-Origin
- Access-Control-Allow-Methods
- Access-Control-Allow-Headers
- Access-Control-Max-Age

### Headers de Exposición
- Server
- X-Powered-By
- X-AspNet-Version
- X-AspNetMvc-Version
- X-Runtime
- X-Generator
- X-Drupal-Cache
- X-Varnish
- Via
- X-Served-By
- X-Client-IP
- X-Server-IP
- X-Backend-Server

## Formato del Archivo de Headers

Si se usa la opción `--file`, el archivo debe tener el siguiente formato:
```
Header-Name1: Value1
Header-Name2: Value2
```

Ejemplo:
```
HTTP/1.1 200 OK
Cache-Control: private
Content-Type: application/json; charset=utf-8
Vary: Accept-Encoding
Server: Microsoft-IIS/8.0
Access-Control-Allow-Origin: *
Access-Control-Allow-Headers: Content-Type, token, ip
Access-Control-Allow-Methods: GET, POST, OPTIONS
X-RateLimit-Limit: 1000
Strict-Transport-Security:  max-age=31536000; includeSubDomains
X-Frame-Options: DENY
Date: Fri, 15 Nov 2024 02:27:36 GMT
Content-Length: 1051

```

## Ejemplos de Uso

### Análisis con nombre de host personalizado:
```bash
python3 hcheck.py --file headers.txt --host https://hacking.cl
```
![Completa](https://i.imgur.com/yK7Qp0d.png)


### Análisis resumido:
```bash
python3 hcheck.py --file headers.txt --host https://hacking.cl --resume
```
![Resumen](https://i.imgur.com/KqKHjEm.png)


## Contribuir

Si encuentras algún bug o tienes alguna sugerencia, por favor:

1. Abre un issue
2. Envía un pull request

## Autor

@unkndown

## Advertencia

Esta herramienta está destinada a ser utilizada para pruebas y auditorías de seguridad autorizadas. El uso de esta herramienta contra sistemas sin autorización expresa puede ser ilegal.