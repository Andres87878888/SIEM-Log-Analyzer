# SIEM Local - Analizador Automatizado de Logs de Red 

Este proyecto es un **SIEM (Security Information and Event Management) Casero** desarrollado en PowerShell. Su objetivo principal es analizar registros de actividad (logs) de servidores web o de red de manera automatizada, detectando firmas de ataques conocidos mediante expresiones regulares (Regex) y ofreciendo un **Playbook de Respuesta a Incidentes** interactivo para la mitigación inmediata de amenazas.

El proyecto incluye un simulador de tráfico para generar logs con ataques reales mezclados con conexiones legítimas para realizar pruebas de concepto seguras.

---

##  Características Principales

*   **Detección de Firmas Multicapa:**
    *    **Severidad Alta:** Inyección SQL (bypasses, consultas estructuradas, comentarios de consulta).
    *    **Severidad Media:** Escaneos automatizados de reconocimiento (firmas de herramientas como Nikto, Nmap, Sqlmap, etc.).
    *    **Severidad Baja:** Intentos fallidos de autenticación (anomalías de fuerza bruta, códigos de estado HTTP 401).
*   **Playbook de Respuesta Integrado:** En caso de detectar alertas, el script despliega recomendaciones técnicas específicas en consola y en el reporte final para mitigar cada tipo de amenaza detectada.
*   **Filtrado de Falsos Positivos:** Expresiones regulares optimizadas para descartar coincidencias de texto comunes que no representan un riesgo real.
*   **Generación de Reportes:** Exporta de manera automática los hallazgos detallados, el resumen de alertas y las guías de mitigación a un archivo estructurado `Alertas_SIEM.txt`.

---

##  Estructura del Repositorio

*   `Analizador_SIEM.ps1`: El motor principal del analizador que procesa los registros y genera las alertas.
*   `Generar_Logs_Prueba.ps1`: Generador de telemetría simulada que crea el archivo `servidor_acceso.log` con datos de tráfico legítimo y patrones de ataque.
*   `Ejecutar_Analizador.bat`: Lanzador rápido que comprueba privilegios de Administrador y ejecuta el SIEM de forma directa con políticas de bypass.
*   `Alertas_SIEM.txt`: Reporte final exportado con las alertas consolidadas y las recomendaciones de seguridad.

---

##  Cómo Utilizar el Proyecto

### 1. Generar los registros de prueba
Antes de correr el analizador, necesitamos simular tráfico en el sistema. Ejecuta el generador de pruebas en PowerShell:
```powershell
powershell -ExecutionPolicy Bypass -File .\Generar_Logs_Prueba.ps1