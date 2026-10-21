# ============================================================
# Inventario NuGet: versiones, CVE y criticidad
# Requiere Windows PowerShell 5.1 y acceso a Internet.
#
# Columnas del reporte:
#   Ruta | Paquete | Version instalada | Ultima version |
#   Version anterior a la ultima | CVE y criticidad (ordenados de mayor a menor)
# ============================================================

$outputFile = Join-Path $PSScriptRoot "inventario_con_cve_criticidad.html"
$packageBaseUrl = "https://api.nuget.org/v3-flatcontainer"
$serviceIndexUrl = "https://data.nuget.org/v3/index.json"

$ErrorActionPreference = "Stop"

# Windows PowerShell 5.1 puede usar TLS antiguo por defecto.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$cveCache = @{}

# ------------------------------------------------------------
# Codificar texto para mostrarlo de forma segura en HTML
# ------------------------------------------------------------
function ConvertTo-HtmlSafe {
    param([AllowNull()][string]$Value)

    if ($null -eq $Value) { return "" }

    return [System.Net.WebUtility]::HtmlEncode($Value)
}

# ------------------------------------------------------------
# Analizar una version NuGet
# ------------------------------------------------------------
function Get-VersionParts {
    param([string]$Version)

    if ([string]::IsNullOrWhiteSpace($Version)) {
        return $null
    }

    $v = $Version.Trim() -replace '^\s*[vV]', ''
    $v = $v -replace '\+.*$', ''

    if ($v -notmatch '^(?<core>\d+(?:\.\d+){0,3})(?:-(?<pre>[0-9A-Za-z.-]+))?$') {
        return $null
    }

    $core = $Matches['core']
    $pre = $Matches['pre']

    $numbers = @(
        $core.Split('.') | ForEach-Object { [long]$_ }
    )

    while ($numbers.Count -lt 3) {
        $numbers += 0L
    }

    return [pscustomobject]@{
        Numbers = $numbers
        Pre     = $pre
    }
}

# ------------------------------------------------------------
# Comparar dos versiones NuGet. Devuelve -1, 0 o 1.
# ------------------------------------------------------------
function Compare-NuGetVersion {
    param(
        [string]$A,
        [string]$B
    )

    $va = Get-VersionParts $A
    $vb = Get-VersionParts $B

    if (-not $va -or -not $vb) {
        throw "No se pudo interpretar una version: '$A' o '$B'."
    }

    for ($i = 0; $i -lt 3; $i++) {
        if ($va.Numbers[$i] -lt $vb.Numbers[$i]) { return -1 }
        if ($va.Numbers[$i] -gt $vb.Numbers[$i]) { return 1 }
    }

    if (-not $va.Pre -and $vb.Pre) { return 1 }
    if ($va.Pre -and -not $vb.Pre) { return -1 }
    if (-not $va.Pre -and -not $vb.Pre) { return 0 }

    $pa = $va.Pre.Split('.')
    $pb = $vb.Pre.Split('.')
    $count = [Math]::Min($pa.Count, $pb.Count)

    for ($i = 0; $i -lt $count; $i++) {
        $na = 0L
        $nb = 0L

        $isNa = [long]::TryParse($pa[$i], [ref]$na)
        $isNb = [long]::TryParse($pb[$i], [ref]$nb)

        if ($isNa -and $isNb) {
            if ($na -lt $nb) { return -1 }
            if ($na -gt $nb) { return 1 }
        }
        elseif ($isNa -and -not $isNb) {
            return -1
        }
        elseif (-not $isNa -and $isNb) {
            return 1
        }
        else {
            $cmp = [string]::Compare(
                $pa[$i],
                $pb[$i],
                [StringComparison]::OrdinalIgnoreCase
            )

            if ($cmp -lt 0) { return -1 }
            if ($cmp -gt 0) { return 1 }
        }
    }

    if ($pa.Count -lt $pb.Count) { return -1 }
    if ($pa.Count -gt $pb.Count) { return 1 }

    return 0
}

# ------------------------------------------------------------
# Obtener la ultima version publicada y la inmediata anterior.
# Incluye versiones estables y prerelease (beta, rc, preview...).
# ------------------------------------------------------------
function Get-LatestVersions {
    param([string]$PackageName)

    $url = "$packageBaseUrl/$($PackageName.ToLowerInvariant())/index.json"

    $data = Invoke-RestMethod `
        -Uri $url `
        -Method Get `
        -ErrorAction Stop

    $versions = @(
        $data.versions |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace($_) -and
            (Get-VersionParts $_) -ne $null
        } |
        Select-Object -Unique
    )

    if ($versions.Count -eq 0) {
        throw "NuGet no devolvio versiones validas para $PackageName."
    }

    # Ordenamiento semantico descendente.
    for ($i = 0; $i -lt $versions.Count; $i++) {
        for ($j = $i + 1; $j -lt $versions.Count; $j++) {
            if ((Compare-NuGetVersion $versions[$i] $versions[$j]) -lt 0) {
                $temp = $versions[$i]
                $versions[$i] = $versions[$j]
                $versions[$j] = $temp
            }
        }
    }

    # La ultima version es la estable mas alta (se ignoran beta, rc, preview...).
    $latestIndex = -1

    for ($i = 0; $i -lt $versions.Count; $i++) {
        if (-not (Get-VersionParts $versions[$i]).Pre) {
            $latestIndex = $i
            break
        }
    }

    if ($latestIndex -lt 0) {
        return [pscustomobject]@{
            Latest   = "Sin version estable"
            Previous = "No disponible"
        }
    }

    # La version anterior es la estable inmediata inferior a la ultima estable
    # (se ignoran beta, rc, preview...).
    $previous = "No disponible"

    for ($i = $latestIndex + 1; $i -lt $versions.Count; $i++) {
        if (-not (Get-VersionParts $versions[$i]).Pre) {
            $previous = $versions[$i]
            break
        }
    }

    return [pscustomobject]@{
        Latest   = $versions[$latestIndex]
        Previous = $previous
    }
}

# ------------------------------------------------------------
# Cargar la base publica de vulnerabilidades de NuGet.
# ------------------------------------------------------------
function Get-NuGetVulnerabilityDatabase {
    $serviceIndex = Invoke-RestMethod `
        -Uri $serviceIndexUrl `
        -Method Get `
        -ErrorAction Stop

    $resource = @(
        $serviceIndex.resources | Where-Object {
            $_.'@type' -match '^VulnerabilityInfo/'
        }
    ) | Select-Object -First 1

    if (-not $resource) {
        throw "La fuente de NuGet no publica el recurso VulnerabilityInfo."
    }

    # PowerShell 5.1 puede devolver el arreglo JSON como un solo objeto;
    # al pasarlo por el pipeline se separa en un elemento por pagina.
    $vulnerabilityIndex = @(
        Invoke-RestMethod `
            -Uri ([string]$resource.'@id') `
            -Method Get `
            -ErrorAction Stop |
        ForEach-Object { $_ }
    )

    $database = @{}

    foreach ($pageInfo in $vulnerabilityIndex) {
        $url = [string]$pageInfo.'@id'

        if ([string]::IsNullOrWhiteSpace($url)) { continue }

        try {
            $page = Invoke-RestMethod `
                -Uri $url `
                -Method Get `
                -ErrorAction Stop

            # Algunas paginas pueden estar vacias.
            if ($page -is [System.Array]) { continue }

            foreach ($property in $page.PSObject.Properties) {
                $id = $property.Name.ToLowerInvariant()

                if (-not $database.ContainsKey($id)) {
                    $database[$id] = @()
                }

                $database[$id] += @($property.Value)
            }
        }
        catch {
            Write-Host "[!] No se pudo cargar una pagina de vulnerabilidades: $url" -ForegroundColor Yellow
            throw
        }
    }

    return $database
}

# ------------------------------------------------------------
# Comprobar si una version pertenece al rango afectado.
# Ejemplos: [1.0.0,2.0.0), (,1.5.0), [1.2.0,)
# ------------------------------------------------------------
function Test-VulnerableVersion {
    param(
        [string]$Installed,
        [string]$Range
    )

    if ([string]::IsNullOrWhiteSpace($Range)) {
        return $false
    }

    $r = $Range.Trim()

    if ($r -match '^\[([^\],]+)\]$') {
        return ((Compare-NuGetVersion $Installed $Matches[1]) -eq 0)
    }

    if ($r -notmatch '^(\[|\()\s*([^,]*)\s*,\s*([^\]\)]*)\s*(\]|\))$') {
        return $false
    }

    $leftBracket = $Matches[1]
    $minVersion = $Matches[2].Trim()
    $maxVersion = $Matches[3].Trim()
    $rightBracket = $Matches[4]

    if ($minVersion) {
        $c = Compare-NuGetVersion $Installed $minVersion

        if ($c -lt 0 -or ($c -eq 0 -and $leftBracket -eq '(')) {
            return $false
        }
    }

    if ($maxVersion) {
        $c = Compare-NuGetVersion $Installed $maxVersion

        if ($c -gt 0 -or ($c -eq 0 -and $rightBracket -eq ')')) {
            return $false
        }
    }

    return $true
}

# ------------------------------------------------------------
# Buscar el CVE en la URL o en la pagina del advisory.
# Si no hay CVE, intenta devolver el id GHSA de la URL.
# ------------------------------------------------------------
function Get-AdvisoryCve {
    param([string]$Url)

    if ([string]::IsNullOrWhiteSpace($Url)) {
        return "Sin CVE"
    }

    if ($cveCache.ContainsKey($Url)) {
        return $cveCache[$Url]
    }

    $result = $null

    if ($Url -match '(?i)CVE-\d{4}-\d{4,}') {
        $result = $Matches[0].ToUpperInvariant()
    }
    else {
        try {
            $response = Invoke-WebRequest `
                -Uri $Url `
                -UseBasicParsing `
                -TimeoutSec 10

            $match = [regex]::Match(
                $response.Content,
                '(?i)CVE-\d{4}-\d{4,}'
            )

            if ($match.Success) {
                $result = $match.Value.ToUpperInvariant()
            }
        }
        catch {
            # Se usa el fallback de abajo.
        }
    }

    if (-not $result) {
        if ($Url -match '(?i)GHSA(-[a-z0-9]{4}){3}') {
            $result = $Matches[0].ToUpperInvariant()
        }
        else {
            $result = "Sin CVE"
        }
    }

    $cveCache[$Url] = $result
    return $result
}

# ------------------------------------------------------------
# Clase CSS segun el nivel de criticidad
# ------------------------------------------------------------
function Get-SeverityClass {
    param([int]$Rank)

    switch ($Rank) {
        3 { return "sev-critical" }
        2 { return "sev-high" }
        1 { return "sev-medium" }
        0 { return "sev-low" }
        default { return "badge-unknown" }
    }
}

# ------------------------------------------------------------
# Inicio
# ------------------------------------------------------------
Write-Host "[*] Cargando base de vulnerabilidades de NuGet..." -ForegroundColor Cyan

try {
    $vulnerabilityDatabase = Get-NuGetVulnerabilityDatabase
    $vulnerabilitySourceAvailable = $true

    Write-Host "[+] Base de vulnerabilidades cargada." -ForegroundColor Green
}
catch {
    $vulnerabilityDatabase = @{}
    $vulnerabilitySourceAvailable = $false

    Write-Host "[!] No se pudo consultar la base de vulnerabilidades: $($_.Exception.Message)" -ForegroundColor Red
}

$totalPaquetes = 0
$totalVulnerables = 0
$rowsHtml = ""

$configFiles = @(
    Get-ChildItem -Path $PSScriptRoot -Recurse -Filter "packages.config" -File
)

foreach ($file in $configFiles) {
    try {
        [xml]$xml = Get-Content `
            -LiteralPath $file.FullName `
            -Raw `
            -ErrorAction Stop

        foreach ($pkg in $xml.packages.package) {
            if (-not $pkg.id -or -not $pkg.version) {
                continue
            }

            $totalPaquetes++

            $packageName = $pkg.id.Trim()
            $installedVersion = $pkg.version.Trim()
            $filePath = $file.FullName

            Write-Host "[$totalPaquetes] Revisando $packageName ($installedVersion)..." -NoNewline

            # --------------------------------------------------
            # Ultima version y version anterior
            # --------------------------------------------------
            $latestVersion = "Desconocido"
            $previousVersion = "Desconocido"

            try {
                $versionInfo = Get-LatestVersions $packageName

                $latestVersion = $versionInfo.Latest
                $previousVersion = $versionInfo.Previous
            }
            catch {
                Write-Host " [Error consultando versiones]" -NoNewline -ForegroundColor Yellow
            }

            # --------------------------------------------------
            # CVE y criticidad
            # --------------------------------------------------
            $cveHtml = ""
            $vulnCount = 0

            if (-not $vulnerabilitySourceAvailable) {
                $cveHtml = '<span class="muted">No se pudo verificar</span>'
            }
            else {
                $key = $packageName.ToLowerInvariant()
                $items = @()

                if ($vulnerabilityDatabase.ContainsKey($key)) {
                    $seen = @{}

                    foreach ($advisory in $vulnerabilityDatabase[$key]) {
                        if (-not (Test-VulnerableVersion `
                                -Installed $installedVersion `
                                -Range ([string]$advisory.versions))) {
                            continue
                        }

                        $url = [string]$advisory.url

                        # Severidad NuGet: 0 baja, 1 media, 2 alta, 3 critica.
                        $rank = -1

                        try {
                            $rank = [int]$advisory.severity
                        }
                        catch {
                            $rank = -1
                        }

                        $severityName = switch ($rank) {
                            0 { "Baja" }
                            1 { "Media" }
                            2 { "Alta" }
                            3 { "Critica" }
                            default { "Desconocida" }
                        }

                        $cve = Get-AdvisoryCve $url

                        # Evitar duplicados del mismo CVE y severidad.
                        $dedupeKey = "$cve|$rank"
                        if ($seen.ContainsKey($dedupeKey)) { continue }
                        $seen[$dedupeKey] = $true

                        $items += [pscustomobject]@{
                            Cve      = $cve
                            Url      = $url
                            Rank     = $rank
                            Severity = $severityName
                        }
                    }
                }

                if ($items.Count -eq 0) {
                    $cveHtml = '<span class="muted">Sin vulnerabilidades conocidas</span>'
                }
                else {
                    $vulnCount = $items.Count

                    # Orden: mas critico primero, luego por nombre de CVE.
                    $sorted = @(
                        $items | Sort-Object `
                            -Property @{ Expression = "Rank"; Descending = $true }, `
                                      @{ Expression = "Cve"; Descending = $false }
                    )

                    $lines = @()

                    foreach ($item in $sorted) {
                        $safeCve = ConvertTo-HtmlSafe $item.Cve
                        $safeSev = ConvertTo-HtmlSafe $item.Severity
                        $sevClass = Get-SeverityClass $item.Rank

                        if ($item.Url -match '^https?://') {
                            $safeUrl = ConvertTo-HtmlSafe $item.Url
                            $cveLink = "<a href=`"$safeUrl`" target=`"_blank`" rel=`"noopener noreferrer`">$safeCve</a>"
                        }
                        else {
                            $cveLink = $safeCve
                        }

                        $lines += "<div class=`"cve-item`">$cveLink <span class=`"badge $sevClass`">$safeSev</span></div>"
                    }

                    $cveHtml = $lines -join "`n"
                    $totalVulnerables++
                }
            }

            $color = "Green"
            if ($vulnCount -gt 0) { $color = "Red" }
            if (-not $vulnerabilitySourceAvailable) { $color = "Yellow" }

            if ($vulnerabilitySourceAvailable) {
                Write-Host " [$vulnCount CVE]" -ForegroundColor $color
            }
            else {
                Write-Host " [CVE no verificados]" -ForegroundColor $color
            }

            # Codificar valores para el HTML.
            $safePath = ConvertTo-HtmlSafe $filePath
            $safeName = ConvertTo-HtmlSafe $packageName
            $safeInstalled = ConvertTo-HtmlSafe $installedVersion
            $safeLatest = ConvertTo-HtmlSafe $latestVersion
            $safePrevious = ConvertTo-HtmlSafe $previousVersion

            $rowsHtml += @"
<tr>
    <td><code>$safePath</code></td>
    <td><strong>$safeName</strong></td>
    <td>$safeInstalled</td>
    <td>$safeLatest</td>
    <td>$safePrevious</td>
    <td>$cveHtml</td>
</tr>
"@
        }
    }
    catch {
        Write-Host "`n[!] Error leyendo $($file.FullName): $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ------------------------------------------------------------
# Construir reporte HTML
# ------------------------------------------------------------
$generationDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$safeGenerationDate = ConvertTo-HtmlSafe $generationDate

if ($vulnerabilitySourceAvailable) {
    $sourceStatus = "Consultada correctamente"
}
else {
    $sourceStatus = "Error de consulta; resultados no concluyentes"
}

$safeSourceStatus = ConvertTo-HtmlSafe $sourceStatus

$htmlContent = @"
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Auditoria de Dependencias NuGet</title>
<style>
body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    margin: 30px;
    background: #f8f9fa;
    color: #333;
}
h1 {
    color: #2c3e50;
    border-bottom: 2px solid #3498db;
    padding-bottom: 10px;
}
.summary {
    background: #fff;
    padding: 15px;
    border-radius: 8px;
    margin-bottom: 20px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.05);
}
.table-wrap {
    overflow-x: auto;
}
table {
    width: 100%;
    border-collapse: collapse;
    background: #fff;
}
th, td {
    padding: 12px 15px;
    text-align: left;
    vertical-align: top;
    border-bottom: 1px solid #e1e8ed;
}
th {
    background: #2c3e50;
    color: #fff;
}
tr:hover {
    background: #f1f4f8;
}
code {
    font-size: 11px;
    overflow-wrap: anywhere;
}
.muted {
    color: #6c757d;
}
.cve-item {
    margin-bottom: 6px;
    white-space: nowrap;
}
.badge {
    padding: 3px 9px;
    border-radius: 12px;
    font-size: 12px;
    font-weight: bold;
    display: inline-block;
}
.sev-critical { background: #721c24; color: #fff; }
.sev-high     { background: #f8d7da; color: #721c24; }
.sev-medium   { background: #fff3cd; color: #856404; }
.sev-low      { background: #d4edda; color: #155724; }
.badge-unknown { background: #e2e3e5; color: #383d41; }
a {
    color: #0056b3;
}
</style>
</head>
<body>
<h1>Reporte de Analisis de Dependencias (SCA)</h1>

<div class="summary">
    <p><strong>Total de dependencias analizadas:</strong> $totalPaquetes</p>
    <p><strong>Dependencias con vulnerabilidades:</strong> $totalVulnerables</p>
    <p><strong>Fuente de vulnerabilidades:</strong> $safeSourceStatus</p>
    <p><strong>Fecha de generacion:</strong> $safeGenerationDate</p>
    <p><em>La ultima version es la estable mas reciente (sin beta, rc ni preview); la version anterior es la estable inmediata inferior a esa. Los CVE de cada paquete se ordenan de mayor a menor criticidad. Los avisos reflejan la fuente consultada y no garantizan la ausencia absoluta de vulnerabilidades.</em></p>
</div>

<div class="table-wrap">
<table>
<thead>
<tr>
    <th>Ruta</th>
    <th>Paquete</th>
    <th>Version instalada</th>
    <th>Ultima version estable</th>
    <th>Version anterior a la ultima</th>
    <th>CVE y criticidad</th>
</tr>
</thead>
<tbody>
$rowsHtml
</tbody>
</table>
</div>
</body>
</html>
"@

$utf8NoBOM = New-Object System.Text.UTF8Encoding $false

[System.IO.File]::WriteAllText(
    $outputFile,
    $htmlContent,
    $utf8NoBOM
)

Write-Host "`n[+] Reporte HTML generado: $outputFile" -ForegroundColor Green