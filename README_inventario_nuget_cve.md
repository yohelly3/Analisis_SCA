# Inventario de paquetes NuGet con CVE y criticidad

Script de PowerShell que analiza los paquetes declarados en los archivos `packages.config` de proyectos .NET Framework 4.8 y genera un reporte HTML con la versión instalada, la última versión estable, la versión estable anterior y las vulnerabilidades conocidas (CVE) con su criticidad.

## Requisitos

- Windows PowerShell 5.1
- Acceso a Internet (consulta NuGet y los avisos de seguridad)
- Proyectos .NET Framework con `packages.config`

## Uso

1. Copia `inventario_nuget_cve.ps1` en la carpeta raíz que contiene tus proyectos.
2. Abre PowerShell en esa carpeta y ejecuta:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\inventario_nuget_cve.ps1
```

El cambio de política de ejecución solo aplica a la sesión actual.

3. Al terminar, se genera `inventario_con_cve_criticidad.html` en la misma carpeta del script.

## Qué hace

1. Descarga la base pública de vulnerabilidades de NuGet.
2. Busca de forma recursiva todos los archivos `packages.config` a partir de la carpeta del script.
3. Por cada paquete toma el id y la versión instalada.
4. Consulta en NuGet la última versión estable y la estable inmediata anterior.
5. Busca vulnerabilidades que afecten la versión instalada y las ordena de mayor a menor criticidad.
6. Genera el reporte HTML con un resumen y una tabla.

## Columnas del reporte

| Columna | Descripción |
|---|---|
| Ruta | Ruta completa del `packages.config` |
| Paquete | Id del paquete NuGet |
| Versión instalada | Versión declarada en `packages.config` |
| Última versión estable | Versión estable más reciente en NuGet (se ignoran beta, rc, preview, etc.) |
| Versión anterior a la última | Versión estable inmediatamente inferior a la última estable |
| CVE y criticidad | CVE que afectan la versión instalada, con enlace al aviso y su criticidad |

El resumen del reporte muestra el total de dependencias analizadas, cuántas tienen vulnerabilidades, el estado de la fuente de vulnerabilidades y la fecha de generación.

### Criticidad

La criticidad es la que publica NuGet para cada aviso, y los CVE de cada paquete se ordenan de mayor a menor:

| Nivel | Color |
|---|---|
| Crítica | Rojo oscuro |
| Alta | Rojo claro |
| Media | Amarillo |
| Baja | Verde |

Si un aviso no incluye CVE, se muestra su identificador GHSA o "Sin CVE".

## Casos especiales

- Si un paquete solo tiene versiones de prueba, la última versión aparece como "Sin version estable".
- Si el paquete no se puede consultar en NuGet, las versiones aparecen como "Desconocido".
- Si la base de vulnerabilidades no se puede cargar, el reporte lo indica y los CVE aparecen como "No se pudo verificar".

## Limitaciones

- El resultado refleja los avisos de la fuente consultada y no garantiza la ausencia de vulnerabilidades.
- Solo se analizan los paquetes declarados en `packages.config`; las dependencias transitivas que no estén listadas ahí no se revisan.
- El script recorre todas las subcarpetas, por lo que también leerá archivos `packages.config` que estén en carpetas como `bin`, `obj` o copias de respaldo.

## Conexiones de red

El script se conecta a:

- `data.nuget.org` y `api.nuget.org`, para el índice de servicio, las versiones de cada paquete y la base de vulnerabilidades. Solo se envían nombres de paquetes en las consultas.
- Las URL de los avisos de seguridad, cuando el CVE no aparece en la propia URL, para intentar identificarlo.

## Estructura del repositorio

```
.
├── inventario_nuget_cve.ps1
└── README.md
```
