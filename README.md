# threat-intel-reports

Repositorio de informes de Threat Intelligence elaborados como proyecto personal de portfolio, con foco en atribución de actores APT, mapeo a MITRE ATT&CK y análisis de campañas documentadas por fuentes públicas (vendor reports, prensa especializada, disclosures gubernamentales).

## Sobre este repositorio

Cada informe se basa exclusivamente en **fuentes públicas ya publicadas** (informes de vendors de seguridad, blogs oficiales, prensa especializada). El objetivo es practicar el proceso de un analista de Threat Intelligence: correlacionar fuentes, estructurar hallazgos, mapear TTPs a MITRE ATT&CK y redactar recomendaciones defensivas accionables, no generar inteligencia original ni divulgar información no pública.

## Estructura

```
threat-intel-reports/
├── reports/          # Informes completos en Markdown, uno por campaña/actor
├── iocs/             # Indicadores de compromiso en formato estructurado (CSV/JSON)
├── templates/         # Plantilla base para nuevos informes
└── README.md
```

## Convención de nombres

- Informes: `reports/AAAA-MM-<actor-o-campaña>.md`
- IOCs: `iocs/<ID-del-actor>_iocs.csv`

## Índice de informes

| Fecha | Actor | Campaña | Enlace |
|---|---|---|---|
| 2026-09 | GTG-20006 / Storm-2945 (Midnight Blizzard / APT29) | CaptiveCrunch | [reports/2026-09-GTG-20006-midnight-blizzard-captivecrunch.md](reports/2026-09-GTG-20006-midnight-blizzard-captivecrunch.md) |

## Metodología

1. Identificación de fuentes primarias (informes oficiales de vendors/CERT).
2. Cruce con fuentes secundarias (prensa especializada) para validar y contextualizar.
3. Mapeo de TTPs a [MITRE ATT&CK](https://attack.mitre.org/) verificando cada ID técnica por técnica (nunca copiando mapeos de terceros sin comprobar).
4. Consolidación de IOCs en formato reutilizable (CSV, compatible con importación a SIEM/TIP).
5. Redacción de recomendaciones defensivas accionables, no genéricas.

## Autor

David Voica — estudiante de Ingeniería en Ciberseguridad (URJC). Proyecto personal orientado a Threat Intelligence / OSINT.

## Licencia y disclaimer

Contenido con fines educativos y de portfolio. Todo el material se basa en fuentes públicas citadas en cada informe; ningún dato aquí presentado constituye inteligencia clasificada ni no divulgada. Ver `LICENSE` para los términos de reutilización del contenido.
