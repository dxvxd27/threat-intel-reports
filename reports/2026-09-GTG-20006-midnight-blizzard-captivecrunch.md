# Informe de Threat Intelligence: GTG-20006 (Midnight Blizzard), campaña CaptiveCrunch

| Campo | Valor |
|---|---|
| **ID interno** | TI-2026-09-001 |
| **Actor(es)** | GTG-20006 / Storm-2945, vinculado a Midnight Blizzard / APT29 / NOBELIUM |
| **Patrocinador asumido** | SVR (Servicio de Inteligencia Exterior de la Federación Rusa) |
| **Clasificación (TLP)** | TLP:CLEAR, basado en fuentes públicas |
| **Nivel de confianza** | Alto, corroborado por dos fuentes primarias independientes |
| **Fecha del informe** | 13 de septiembre de 2026 |
| **Analista** | David Voica |
| **Periodo cubierto** | Diciembre 2025 a agosto 2026 |

---

## 1. Resumen ejecutivo

Entre diciembre de 2025 y agosto de 2026, Anthropic y Microsoft documentaron por separado una misma campaña de ciberespionaje operada por un actor vinculado a Midnight Blizzard (también conocido como APT29 o NOBELIUM), atribuido al Servicio de Inteligencia Exterior de Rusia (SVR).

Anthropic identificó y bloqueó el uso indebido de su modelo Claude bajo el identificador interno GTG-20006. El actor lo usaba prácticamente en cada fase del ataque: reconocimiento automatizado, generación de infraestructura de phishing, ejecución de comandos contra sistemas víctima, extracción de credenciales y, lo más llamativo, reconstrucción autónoma del malware cuando este era detectado por los productos de seguridad de la víctima.

Por su lado, Microsoft publicó el 31 de julio de 2026 un análisis técnico de una campaña activa desde mayo de 2026 bautizada como CaptiveCrunch, atribuida al subgrupo Storm-2945 dentro del clúster Midnight Blizzard. Esta campaña secuestra los portales cautivos de las redes Wi-Fi de hoteles y centros de conferencias para redirigir a viajeros corporativos hacia infraestructura maliciosa, con el objetivo de robar credenciales de Microsoft 365 mediante device code phishing y desplegar el RAT CornFlake junto al infostealer ChocoShell.

Entre los objetivos de ambas campañas están la inteligencia militar y el gobierno de Ucrania, misiones diplomáticas europeas, organizaciones vinculadas a política exterior estadounidense, contratistas de defensa (sobre todo fabricantes de drones y sistemas de visión) y viajeros corporativos alojados en hoteles con la red comprometida. Se documentó la exfiltración de más de 300.000 registros de identidad nacional de una autoridad gubernamental del norte de África, más de 500.000 registros de un registro mercantil, y el robo de SDKs y firmware propietario de sistemas de visión para drones.

La coincidencia de fechas, la victimología solapada, el uso compartido de device code phishing como vector de entrada y las técnicas de exfiltración vía Microsoft Graph apuntan con bastante seguridad a que GTG-20006 y la infraestructura de CaptiveCrunch pertenecen al mismo ecosistema operativo de Midnight Blizzard, probablemente repartido en sub-equipos (Storm-2945 sería uno de ellos) bajo una misma cadena de mando.

---

## 2. Atribución

### 2.1 Identidad del actor

| Alias | Quién lo usa |
|---|---|
| Midnight Blizzard | Microsoft (nombre actual) |
| APT29 | Mandiant y la comunidad de seguridad en general |
| NOBELIUM | Microsoft, nombre anterior a 2023 |
| Cozy Bear | CrowdStrike |
| GTG-20006 | Anthropic, identificador interno de este clúster |
| Storm-2945 | Microsoft, sub-clúster específico tras CaptiveCrunch |

### 2.2 Patrocinador y motivación

Ambas fuentes atribuyen la actividad al SVR, el servicio de inteligencia exterior ruso. La motivación es espionaje de inteligencia estratégica: recopilar información diplomática, militar y tecnológica de interés para el estado ruso, con especial foco en todo lo relacionado con la guerra en Ucrania.

### 2.3 Base de la atribución

Anthropic identificó a un operador de habla rusa con el alias "JackPoterz" interactuando directamente con Claude para tareas operativas, y comparó el patrón de comportamiento con reporting público previo sobre Midnight Blizzard.

Microsoft, por su parte, atribuye Storm-2945 por solapamientos técnicos y operativos con Storm-2372 (otro clúster ya atribuido a Midnight Blizzard): el mismo uso de device code phishing como acceso inicial, exfiltración de correo vía Microsoft Graph API, y una victimología parecida (gobierno, cuerpo diplomático, ONG y sector TI).

### 2.4 Nivel de confianza

Alto. La atribución no descansa en una sola fuente: dos empresas con visibilidad técnica muy distinta (un proveedor de modelos de IA que observa el uso de su propia herramienta, y un proveedor de identidad y cloud que observa el abuso de su ecosistema OAuth/M365) llegan a la misma conclusión por caminos independientes, con solapamiento temporal y de TTPs verificable.

---

## 3. Cronología de la campaña

| Fecha | Evento |
|---|---|
| Dic 2025 | Arranca el periodo de actividad que documenta Anthropic (uso de Claude por GTG-20006) |
| Feb 2026 | Microsoft observa el inicio de operaciones de phishing OAuth / device code |
| 28 abr 2026 | Primera infraestructura de Adversary-in-the-Middle (AitM) detectada por Microsoft |
| May 2026 | Empieza la manipulación de redes de portales cautivos, el núcleo de CaptiveCrunch |
| 1 jul 2026 | Infraestructura C2 y de staging de ChocoShell activa |
| 16 jul 2026 | Se observan redirects de autenticación por device code |
| 23 jul 2026 | ReliaQuest publica de forma independiente hallazgos sobre secuestro de DNS en redes hoteleras |
| 31 jul 2026 | Microsoft publica el análisis técnico de CaptiveCrunch |
| Ago 2026 | Termina el periodo de actividad que cubre el informe de Anthropic |
| 10 sep 2026 | Anthropic publica "Detecting and countering misuse of AI: September 2026", donde revela GTG-20006 |

La tabla mezcla fechas de dos fuentes que observan cosas distintas: Anthropic ve el uso del modelo de IA, Microsoft ve la infraestructura de red y el malware en sí. No son necesariamente hitos de la misma sub-operación, sino del mismo actor trabajando en paralelo en dos frentes.

---

## 4. TTPs mapeados a MITRE ATT&CK

| Táctica | Técnica | ID | Cómo se aplica en este caso |
|---|---|---|---|
| Reconnaissance | Gather Victim Identity Information | T1589 | Uso de Claude para automatizar el fingerprinting de sistemas de correo y acceso remoto, y construir listas de objetivos a partir de fuentes abiertas |
| Resource Development | Establish Accounts / Acquire Infrastructure | T1585 / T1583 | Registro de dominios typosquat de Microsoft 365 (ms365-live[.]com, m365-owa[.]com, etc.) para las páginas de phishing |
| Initial Access | Phishing: Spearphishing Link | T1566.002 | Enlaces de device code / OAuth enviados a las víctimas para iniciar el robo de sesión |
| Initial Access | Adversary-in-the-Middle: Evil Twin | T1557.004 | Secuestro y manipulación de portales cautivos Wi-Fi en hoteles y centros de conferencias para interponerse en el tráfico de los huéspedes |
| Execution | User Execution: Malicious Copy and Paste (ClickFix) | T1204.004 | Prompts falsos de actualización de SO o navegador que inducen a la víctima a pegar y ejecutar comandos maliciosos |
| Credential Access | Multi-Factor Authentication Interception | T1111 | Abuso del flujo legítimo de device code de Microsoft para capturar tokens de sesión y saltarse el MFA |
| Credential Access | Credentials from Password Stores: Credentials from Web Browsers | T1555.003 | ChocoShell extrae contraseñas y cookies guardadas en Chrome, Edge y Firefox, incluido el bypass de Chrome App-Bound Encryption |
| Credential Access | Input Capture: Keylogging | T1056.001 | CornFlake registra las pulsaciones de teclado |
| Collection | Screen Capture | T1113 | Capturas de pantalla periódicas por parte de CornFlake |
| Collection | Audio Capture / Video Capture | T1123 / T1125 | Captura de audio y vídeo desde el dispositivo comprometido |
| Collection | Clipboard Data | T1115 | Monitorización del portapapeles |
| Collection | Email Collection: Remote Email Collection | T1114.002 | Exportación masiva de buzones de correo vía Microsoft Graph API (la herramienta que llaman "Embassy Kit") |
| Persistence | Create or Modify System Process: Windows Service | T1543.003 | CornFlake se instala como servicio con nombres tipo "svchost32" o "Cloud Sync Service" |
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 | Persistencia adicional vía claves de registro |
| Persistence | Scheduled Task/Job | T1053.005 | Tareas programadas como mecanismo de persistencia redundante |
| Defense Evasion | Abuse Elevation Control Mechanism: Bypass User Account Control | T1548.002 | Tres métodos de bypass de UAC en ChocoShell (SilentCleanup, wsreset.exe, sdclt.exe) |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 | Deshabilitación de AMSI vía reflexión de .NET |
| Defense Evasion | Virtualization/Sandbox Evasion: System Checks | T1497.001 | Comprobaciones de temporización para detectar si el malware corre en una máquina virtual |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | C2 de CornFlake sobre un protocolo JSON propio, con intercambio de claves ECDH P-256 |
| Command and Control | Encrypted Channel: Asymmetric Cryptography | T1573.002 | Cifrado de la sesión mediante ECDH y SHA-256 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | Los datos salen por el mismo canal C2 |
| TTP emergente | Reconstrucción autónoma de malware asistida por IA | sin ID en ATT&CK Enterprise | Agentes de IA reconfigurando y recompilando los implantes de forma autónoma cuando el EDR o el antivirus los detecta |

La última fila no tiene ID porque MITRE ATT&CK Enterprise todavía no cataloga esta capacidad como técnica propia. MITRE está empezando a modelar comportamientos de este tipo en ATLAS, el framework hermano de ATT&CK centrado en ataques a sistemas de IA, pero a fecha de este informe no existe un ID equivalente en Enterprise.

---

## 5. Infraestructura e IOCs

Lista de indicadores consolidada de ambas fuentes primarias. El fichero estructurado está en [`/iocs/GTG-20006_iocs.csv`](../iocs/GTG-20006_iocs.csv).

### 5.1 Dominios

| Dominio | Función |
|---|---|
| ms365-live[.]com | Phishing / redirección de device code |
| ms365-device[.]com | Phishing / redirección de device code |
| m365-owa[.]com | Página falsa de OWA |
| owa-ms365[.]com | Página falsa de OWA |
| cdncounter[.]net | Infraestructura de staging/C2 |
| meridian-protocol[.]org | Infraestructura de staging/C2 |

### 5.2 Direcciones IP

| IP | Rol observado |
|---|---|
| 104.145.210[.]184 | Infraestructura GTG-20006 (Anthropic) |
| 31.57.243[.]154 | Infraestructura compartida entre ambas fuentes |
| 104.194.151[.]133 | Infraestructura GTG-20006 (Anthropic) |
| 38.146.28[.]75 | C2 de CaptiveCrunch |
| 38.146.28[.]132 | C2 de CaptiveCrunch |
| 104.194.159[.]150 | C2 de CaptiveCrunch |
| 107.189.26[.]194 | C2 de CaptiveCrunch |
| 213.145.86[.]112 | C2 dedicado de ChocoShell |

### 5.3 Hashes de malware (SHA-256)

| Hash | Familia |
|---|---|
| `918fa52ae45ed60ba7cc8bdc99c3cbe9ab92e0375ec31fc05d0d4513be11c593` | CornFlake, RAT en Go |
| `be99857449d2856dd5a84e21c8a3d5e0e01456adb44062ddec5a6b4970d8d42c` | ChocoShell, infostealer en PowerShell |

### 5.4 Arsenal de malware, referencia completa

| Nombre | Plataforma | Tipo |
|---|---|---|
| CornFlake | Windows | RAT en Go: keylogging, captura de pantalla/audio/vídeo, robo de credenciales de navegador |
| ChocoShell | Windows | Infostealer en PowerShell, solo en memoria |
| FruitStone | Panel C2 web | SPA que imita una consola llamada "CloudSync Console", bajo la marca falsa "Acuity Systems, Inc." |
| PowerChrome, WUEngine, Shadow C2, MiniPlasma, CloudSyncSvc | Windows | Familia adicional de implantes reportada por Anthropic |
| GiftDrop (rebrand de GiftsExpress) | Android | RAT de vigilancia |
| DarkSword | iOS | Cadena de exploits |

Estos indicadores tienen vida útil corta, dominios e IPs de este tipo de infraestructura suelen rotarse en semanas.

---

## 6. Análisis de objetivos e impacto

### 6.1 Sectores y perfiles objetivo

Gobierno y defensa: inteligencia militar ucraniana, agencias gubernamentales europeas, misiones diplomáticas y organizaciones vinculadas a política exterior de EE. UU.

Industria de defensa: contratistas especializados en drones y sistemas de visión, con robo confirmado de SDKs y firmware propietario.

Sector hotelero: no es el objetivo final, sino el vector para llegar a huéspedes de interés, funcionarios, diplomáticos, ejecutivos que viajan.

Viajeros corporativos en general: cualquiera conectado a la red Wi-Fi comprometida de un hotel o centro de conferencias es un blanco potencial de recolección oportunista, aunque el interés real de inteligencia se concentra en perfiles concretos.

### 6.2 Impacto documentado

Compromiso confirmado de más de 20 organizaciones distintas en Ucrania y Europa. Exfiltración de más de 300.000 registros de identidad nacional de una autoridad gubernamental del norte de África, y más de 500.000 registros de un registro mercantil. Robo de propiedad intelectual sensible, SDKs y firmware de sistemas de visión para drones, con implicaciones directas para la ventaja tecnológica militar de las víctimas. También se documentó el secuestro de cuentas de WhatsApp mediante navegadores headless (con la librería WPPConnect) para acceder a comunicaciones privadas.

### 6.3 Por qué importa el uso de IA en este caso

Lo diferente de GTG-20006 frente a campañas anteriores de Midnight Blizzard no es el objetivo, que encaja con su patrón histórico, sino la escala y la velocidad operativa que la IA generativa permite. Con ayuda de agentes de IA, un equipo humano relativamente pequeño puede automatizar el reconocimiento, generar y adaptar infraestructura de phishing, ejecutar comandos post-explotación y, lo más relevante para la defensa, reconstruir el malware de forma autónoma en cuanto es detectado, acortando la ventana de detección y respuesta de la que dependen los equipos de blue team.

---

## 7. Recomendaciones defensivas

### 7.1 Contra device code phishing y AitM

Deshabilitar o restringir el flujo de autenticación por device code en Entra ID/Microsoft 365 salvo en escenarios que realmente lo necesiten. Aplicar Conditional Access basado en ubicación y riesgo, y exigir MFA resistente a phishing (FIDO2/passkeys) en lugar de OTP o push, que sí son vulnerables a AitM. Monitorizar los logs de Entra ID (SignInLogs) buscando patrones raros de autenticación por device code desde IPs o user agents inusuales.

### 7.2 Contra el secuestro de portales cautivos

Al viajar, evitar autenticarse en cuentas corporativas usando el Wi-Fi de hoteles o centros de conferencias; mejor VPN corporativa siempre activa o tethering desde el móvil. Para equipos de seguridad, forzar DNS over HTTPS/TLS en los dispositivos gestionados para neutralizar la manipulación DNS del portal cautivo. Y formación específica sobre ClickFix: ningún proceso legítimo de actualización pide copiar y pegar un comando en una terminal.

### 7.3 Contra el malware (CornFlake / ChocoShell)

Detección basada en comportamiento (EDR) para: servicios creados con nombres que imitan procesos del sistema como "svchost32", desactivación de AMSI vía reflexión de .NET, y los tres métodos de bypass de UAC mencionados (SilentCleanup, wsreset.exe, sdclt.exe). Vigilar el uso de Chrome DevTools Protocol para extraer cookies en texto plano, no es un patrón normal en la mayoría de entornos corporativos. Threat hunting retroactivo con los hashes e IOCs de la sección 5, aunque lo más probable es que la infraestructura ya haya rotado.

### 7.4 Recomendación estratégica frente al uso ofensivo de IA

Los defensores deben asumir que el tiempo de reconstrucción de malware tras ser detectado se está acortando gracias a agentes de IA del lado ofensivo. Eso refuerza la necesidad de detectar por comportamiento y TTPs, que cambian poco, en lugar de depender solo de firmas estáticas que el adversario puede regenerar en minutos. También conviene reportar a los proveedores de modelos de IA cualquier evidencia de abuso detectada, que es de hecho el mecanismo por el que salió a la luz la fuente principal de este informe.

---

## 8. Referencias

1. Anthropic. *Detecting and countering misuse of AI: September 2026.* 10 de septiembre de 2026. https://www.anthropic.com/threat-intelligence-report-september-2026
2. Microsoft Threat Intelligence. *CaptiveCrunch: Midnight Blizzard targets travelers worldwide for malware delivery and credential theft.* 31 de julio de 2026. https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/
3. The Hacker News. *Russian State-Sponsored Hackers Use Claude to Rebuild Malware After Detection.* Septiembre de 2026. https://thehackernews.com/2026/09/russian-state-sponsored-hackers-use.html
4. The Hacker News. *Claude Used to Automate Exploitation and Data Theft Across Multiple Victims.* Septiembre de 2026. https://thehackernews.com/2026/09/claude-used-to-automate-exploitation.html
5. Zscaler ThreatLabz. *Midnight Blizzard launches CaptiveCrunch.* 2026. https://www.zscaler.com/blogs/security-research/captivecrunch-midnight-blizzard-weaponizes-hotel-wi-fi-captive-portals
6. Infosecurity Magazine. *Midnight Blizzard Targets Travelers via Captive Portals.* 2026. https://www.infosecurity-magazine.com/news/captivecrunch-midnight-blizzard/
7. MITRE ATT&CK. *Enterprise Matrix.* https://attack.mitre.org/matrices/enterprise/

---

Informe elaborado con fines educativos y de portfolio, a partir de fuentes públicas ya publicadas por Anthropic y Microsoft. No incluye información no divulgada ni análisis de inteligencia clasificada.
