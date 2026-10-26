# OSINT Domain & Security Analyzer

Una herramienta ligera desarrollada en Python para realizar reconocimiento de dominios, análisis de registros DNS, geolocalización de IPs y auditoría rápida de cabeceras de seguridad HTTP.

---

## Características

* **Bucle Interactivo:** Realiza múltiples escaneos consecutivos sin necesidad de reiniciar la herramienta.
* **Resolución DNS Avanzada:** Consulta registros clave (`A`, `MX`, `NS`, `TXT`) usando `dnspython`.
* **Geolocalización de IP:** Obtiene país, ciudad y proveedor de servicios (ISP) en tiempo real.
* **Auditoría de Cabeceras HTTP:** Verifica la presencia de medidas críticas de seguridad (HSTS, CSP, X-Frame-Options, etc.).
* **Interfaz Visual Atractiva:** Construida con `rich` para mostrar banners limpios, paneles informativos y tablas estructuradas a color.

---

## Requisitos e Instalación

Asegúrate de tener Python 3.8 o superior instalado en tu sistema.

   ```bash
   git clone https://github.com/S4IM0N-12/Analizador-de-dominios.git
   cd Analizador-de-dominios/
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
## Ejecutar el script
   ```bash
   python analyzer.py