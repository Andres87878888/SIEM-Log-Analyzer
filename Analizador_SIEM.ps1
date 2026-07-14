clear
$LogPath = ".\servidor_acceso.log"
$ReportPath = ".\Alertas_SIEM.txt"

# Validar que el archivo de logs exista
if (-not (Test-Path $LogPath)) {
    Write-Host "[-] ERROR: No se encontro el archivo de logs en $LogPath" -ForegroundColor Red
    Write-Host "[!] Por favor, ejecuta primero el generador de logs (Generar_Logs_Prueba.ps1)." -ForegroundColor Yellow
    Exit
}

# Leer el contenido del log
$LogLines = Get-Content -Path $LogPath

Write-Host "==========================================================" -ForegroundColor DarkCyan
Write-Host "         SIEM LOCAL - ANALIZADOR DE REGISTROS (LOGS)      " -ForegroundColor DarkCyan
Write-Host "==========================================================" -ForegroundColor DarkCyan
Write-Host "Analizando archivo: $LogPath" -ForegroundColor Gray
Write-Host "Lineas procesadas: $($LogLines.Count)" -ForegroundColor Gray
Write-Host "Fecha del analisis: $(Get-Date)" -ForegroundColor Gray
Write-Host ""

# Contadores de severidad para el resumen
$AlertasBajas = 0
$AlertasMedias = 0
$AlertasAltas = 0

# Crear la cabecera del reporte de salida en TXT
$ReportHeader = @"
==========================================================
              REPORTE DE INCIDENTES - SIEM LOCAL
==========================================================
Fecha del analisis: $(Get-Date)
Archivo auditado: $LogPath
==========================================================
"@
$ReportHeader | Out-File -FilePath $ReportPath -Force -Encoding utf8

# Procesar línea por línea buscando firmas de ataques conocidos
foreach ($Line in $LogLines) {
    
    # 1. DETECCION DE SQL INJECTION (Severidad: ALTA)
    if ($Line -match "(UNION\s+SELECT|SELECT\s+.*FROM|'\s*OR\s*'\d+'\s*=\s*'\d+|'\s*OR\s*\d+\s*=\s*\d+|--\s*$|\x27\s*(AND|OR|UNION)\s+)") {
        $AlertasAltas++
        Write-Host "[!] ALERTA ALTA: Intento de SQL Injection detectado!" -ForegroundColor Red
        Write-Host "    Registro: $Line" -ForegroundColor Gray
        Write-Host ""
        
        "[!] ALERTA ALTA: Intento de SQL Injection detectado`n    $Line`n" | Out-File -FilePath $ReportPath -Append -Encoding utf8
        continue
    }

    # 2. DETECCION DE ESCANEO DE VULNERABILIDADES (Severidad: MEDIA)
    if ($Line -match "(Nikto|Nmap|Dirb|Acunetix|sqlmap)") {
        $AlertasMedias++
        Write-Host "[!] ALERTA MEDIA: Escaneo automatizado detectado (Reconocimiento)" -ForegroundColor Yellow
        Write-Host "    Registro: $Line" -ForegroundColor Gray
        Write-Host ""
        
        "[!] ALERTA MEDIA: Escaneo automatizado detectado`n    $Line`n" | Out-File -FilePath $ReportPath -Append -Encoding utf8
        continue
    }

    # 3. DETECCION DE POSIBLE FUERZA BRUTA (Severidad: BAJA)
    if ($Line -match "STATUS: 401" -or $Line -match "Intento fallido") {
        $AlertasBajas++
        Write-Host "[!] ALERTA BAJA: Intento fallido de inicio de sesion" -ForegroundColor DarkYellow
        Write-Host "    Registro: $Line" -ForegroundColor Gray
        Write-Host ""
        
        "[!] ALERTA BAJA: Intento fallido de inicio de sesion`n    $Line`n" | Out-File -FilePath $ReportPath -Append -Encoding utf8
        continue
    }
}

# Mostrar resumen final en pantalla
Write-Host "==========================================================" -ForegroundColor DarkCyan
Write-Host "                   RESUMEN DE SEGURIDAD                   " -ForegroundColor DarkCyan
Write-Host "==========================================================" -ForegroundColor DarkCyan
Write-Host " [+] Alertas Altas (Criticas):  $AlertasAltas" -ForegroundColor Red
Write-Host " [+] Alertas Medias (Sosp.):    $AlertasMedias" -ForegroundColor Yellow
Write-Host " [+] Alertas Bajas (Info):      $AlertasBajas" -ForegroundColor DarkYellow
Write-Host "==========================================================" -ForegroundColor DarkCyan

$TotalAlertas = $AlertasAltas + $AlertasMedias + $AlertasBajas

# MÓDULO DE RECOMENDACIONES (PLAYBOOK DE RESPUESTA)
if ($TotalAlertas -gt 0) {
    Write-Host "[!] SE HAN DETECTADO EVENTOS ANOMALOS EN EL SISTEMA." -ForegroundColor Red
    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Red
    Write-Host "         PLAYBOOK DE MITIGACION Y RESPUESTA RECOMENDADA   " -ForegroundColor Red
    Write-Host "==========================================================" -ForegroundColor Red
    
    $RecomendacionesTxt = "`n==========================================================`n" +
                          "         PLAYBOOK DE MITIGACION Y RESPUESTA RECOMENDADA   `n" +
                          "==========================================================`n"

    if ($AlertasAltas -gt 0) {
        Write-Host "[-] PARA INYECCION SQL (ALERTA ALTA):" -ForegroundColor Red
        Write-Host "    * Sanitizar y parametrizar todas las consultas a la base de datos." -ForegroundColor Gray
        Write-Host "    * Validar los inputs de usuario antes de procesarlos." -ForegroundColor Gray
        Write-Host "    * Implementar un Web Application Firewall (WAF) para bloquear payloads." -ForegroundColor Gray
        Write-Host ""
        
        $RecomendacionesTxt += "[-] PARA INYECCION SQL (ALERTA ALTA):`n" +
                               "    * Sanitizar y parametrizar todas las consultas a la base de datos.`n" +
                               "    * Validar los inputs de usuario antes de procesarlos.`n" +
                               "    * Implementar un Web Application Firewall (WAF) para bloquear payloads.`n`n"
    }

    if ($AlertasMedias -gt 0) {
        Write-Host "[-] PARA ESCANEOS DE RECONOCIMIENTO (ALERTA MEDIA):" -ForegroundColor Yellow
        Write-Host "    * Bloquear temporalmente las IPs atacantes en el Firewall perimetral." -ForegroundColor Gray
        Write-Host "    * Deshabilitar cabeceras HTTP innecesarias que revelen versiones de software." -ForegroundColor Gray
        Write-Host "    * Configurar limitadores de peticiones (Rate Limiting) para entorpecer los escaneos." -ForegroundColor Gray
        Write-Host ""

        $RecomendacionesTxt += "[-] PARA ESCANEOS DE RECONOCIMIENTO (ALERTA MEDIA):`n" +
                               "    * Bloquear temporalmente las IPs atacantes en el Firewall perimetral.`n" +
                               "    * Deshabilitar cabeceras HTTP innecesarias que revelen versiones de software.`n" +
                               "    * Configurar limitadores de peticiones (Rate Limiting) para entorpecer los escaneos.`n`n"
    }

    if ($AlertasBajas -gt 0) {
        Write-Host "[-] PARA FUERZA BRUTA / INTENTOS FALLIDOS (ALERTA BAJA):" -ForegroundColor DarkYellow
        Write-Host "    * Implementar politicas de bloqueo de cuenta tras 3 o 5 intentos fallidos." -ForegroundColor Gray
        Write-Host "    * Habilitar el Factor de Doble Autenticacion (2FA) de forma obligatoria." -ForegroundColor Gray
        Write-Host "    * Monitorear si las peticiones provienen de ubicaciones inusuales o VPNs." -ForegroundColor Gray
        Write-Host ""

        $RecomendacionesTxt += "[-] PARA FUERZA BRUTA / INTENTOS FALLIDOS (ALERTA BAJA):`n" +
                               "    * Implementar politicas de bloqueo de cuenta tras 3 o 5 intentos fallidos.`n" +
                               "    * Habilitar el Factor de Doble Autenticacion (2FA) de forma obligatoria.`n" +
                               "    * Monitorear si las peticiones provienen de ubicaciones inusuales o VPNs.`n`n"
    }

    Write-Host "[i] El reporte completo y las recomendaciones se han guardado en:" -ForegroundColor Gray
    Write-Host "    $ReportPath" -ForegroundColor Green
    Write-Host "==========================================================" -ForegroundColor DarkCyan
} else {
    Write-Host "[+] No se encontraron patrones sospechosos en el archivo." -ForegroundColor Green
}
Write-Host ""

# Guardar resumen y recomendaciones finales al archivo TXT
$Summary = @"
==========================================================
                   RESUMEN DE ALERTAS
==========================================================
Alertas Altas:  $AlertasAltas
Alertas Medias: $AlertasMedias
Alertas Bajas:  $AlertasBajas
==========================================================
"@
$Summary | Out-File -FilePath $ReportPath -Append -Encoding utf8
$RecomendacionesTxt | Out-File -FilePath $ReportPath -Append -Encoding utf8

Read-Host "Presiona Enter para finalizar"