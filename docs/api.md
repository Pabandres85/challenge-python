# Documentación de API — challenge-python

Base URL en Docker: `http://app:5000`
Base URL local: `http://localhost:5000` (requiere `KEY_PATH` y `BASELINE_PATH` configurados)

---

## GET /status

Health check de la aplicación.

**Autenticación**: No requerida

**Response 200**
```json
{"status": "ok"}
```

**Ejemplo**
```bash
curl http://app:5000/status
```

---

## GET /users

Lista los nombres de usuario registrados en la base de datos.

**Autenticación**: No requerida

**Response 200**
```json
{
  "users": ["alice", "bob", "admin"]
}
```

**Errores**

| Código | Causa |
|--------|-------|
| 500 | Error de conexión a la base de datos |

**Ejemplo**
```bash
curl http://app:5000/users
```

---

## GET /admin/flag

Retorna la flag del CTF. Requiere un JWT válido firmado con RS256 cuyo payload incluya un usuario con rol `cloudsec` en la base de datos.

**Autenticación**: Bearer Token (JWT RS256)

**Headers requeridos**
```
Authorization: Bearer <token>
```

**Payload JWT esperado**
```json
{
  "user": "bob",
  "role": "cloudsec"
}
```

**Response 200**
```json
{
  "flag": "🎉 FLAG{congrats_you_made_it}",
  "message": "¡Bien hecho! Descubriste el acceso correcto."
}
```

**Errores**

| Código | Causa |
|--------|-------|
| 403 | Token ausente, firma inválida, algoritmo incorrecto, usuario sin rol `cloudsec`, o claims `user`/`role` faltantes |

**Ejemplo**
```python
import jwt
from cryptography.hazmat.primitives import serialization

with open("app/keys/private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

token = jwt.encode({"user": "bob", "role": "cloudsec"}, private_key, algorithm="RS256")
# curl -H "Authorization: Bearer <token>" http://app:5000/admin/flag
```

---

## POST /resources/ingest

Recibe el estado actual de uno o más recursos de infraestructura, los persiste en `resources_current`, los compara contra el baseline almacenado en `resources_baseline`, y guarda los drifts detectados en la tabla `drifts`.

Si `resources_baseline` está vacía, se siembra automáticamente desde `data/baseline.json`.

**Autenticación**: No requerida

**Content-Type**: `application/json`

**Request body**

Acepta un objeto único o un array de objetos. Cada recurso debe tener al menos `resource_id` y `type`.

```json
[
  {
    "resource_id": "vm-001",
    "type": "VM",
    "instance_type": "t2.large",
    "tags": {
      "environment": "production"
    },
    "security_groups": [
      {
        "group_id": "sg-001",
        "rules": [
          {"protocol": "tcp", "port": 80, "source": "0.0.0.0/0"},
          {"protocol": "tcp", "port": 22, "source": "0.0.0.0/0"}
        ]
      }
    ]
  },
  {
    "resource_id": "lb-001",
    "type": "LoadBalancer",
    "listeners": [
      {"protocol": "HTTP",  "port": 80},
      {"protocol": "HTTPS", "port": 443}
    ],
    "tags": {
      "environment": "production"
    }
  }
]
```

**Campos por tipo de recurso**

| Campo | Tipo | Aplica a | Descripción |
|-------|------|----------|-------------|
| `resource_id` | string | Todos | Identificador único del recurso (**requerido**) |
| `type` | string | Todos | Tipo de recurso: `VM`, `LoadBalancer` (**requerido**) |
| `instance_type` | string | VM | Tipo de instancia (e.g. `t2.micro`) |
| `tags` | object | Todos | Pares clave-valor de etiquetas |
| `security_groups` | array | VM | Grupos de seguridad con sus reglas |
| `listeners` | array | LoadBalancer | Listeners HTTP/HTTPS |

**Response 200**
```json
{
  "processed": 2,
  "drifts_detected": 4,
  "drifts": [
    {
      "resource_id": "vm-001",
      "type": "VM",
      "description": "Instance type changed from t2.micro to t2.large",
      "severity": "High"
    },
    {
      "resource_id": "vm-001",
      "type": "VM",
      "description": "Security rule added: tcp/22 from 0.0.0.0/0",
      "severity": "Critical"
    },
    {
      "resource_id": "vm-001",
      "type": "VM",
      "description": "Tag 'owner' missing",
      "severity": "Medium"
    },
    {
      "resource_id": "lb-001",
      "type": "LoadBalancer",
      "description": "Listener added: HTTPS/443",
      "severity": "Low"
    }
  ]
}
```

**Severidades**

| Severidad | Ejemplos |
|-----------|----------|
| `Critical` | Puerto de administración abierto (SSH/RDP) desde `0.0.0.0/0` |
| `High` | Cambio de tipo de instancia, regla de firewall eliminada, listener eliminado |
| `Medium` | Tag faltante o con valor incorrecto, recurso nuevo sin baseline |
| `Low` | Listener agregado (e.g. HTTPS), cambio no crítico de configuración |

**Errores**

| Código | Causa |
|--------|-------|
| 400 | Body vacío, JSON inválido, o recurso sin `resource_id` o `type` |
| 500 | Error interno de BD u otro error no controlado |

**Ejemplo**
```bash
curl -X POST http://app:5000/resources/ingest \
  -H "Content-Type: application/json" \
  -d @data/current.json
```

---

## GET /drifts/summary

Retorna un resumen de los drifts detectados agrupados por tipo de recurso y por severidad.

**Autenticación**: No requerida

**Response 200**
```json
{
  "by_type": {
    "VM": 3,
    "LoadBalancer": 1
  },
  "by_severity": {
    "Critical": 1,
    "High": 1,
    "Medium": 1,
    "Low": 1
  },
  "total": 4
}
```

El campo `total` es la suma de todos los valores en `by_type`.

**Notas**
- Si no se ha ejecutado ningún `POST /resources/ingest`, retorna `{"by_type": {}, "by_severity": {}, "total": 0}`.
- Los drifts se reemplazan en cada ingest: el summary siempre refleja el estado actual.

**Errores**

| Código | Causa |
|--------|-------|
| 500 | Error interno de BD |

**Ejemplo**
```bash
curl http://app:5000/drifts/summary
```

---

## Flujo completo de uso

```bash
# 1. Verificar que la API está arriba
curl http://app:5000/status

# 2. Ingestar el estado actual (detecta 4 drifts con los datos de ejemplo)
curl -X POST http://app:5000/resources/ingest \
  -H "Content-Type: application/json" \
  -d @data/current.json

# 3. Consultar el resumen de drifts
curl http://app:5000/drifts/summary

# 4. (CTF) Capturar la flag
python scripts/ctf_exploit.py
```