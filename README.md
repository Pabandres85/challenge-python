# Desafío Técnico de Seguridad y Desarrollo en la Nube

¡Bienvenido/a al desafío técnico de seguridad y desarrollo! Este ejercicio evalúa tus habilidades para construir y asegurar APIs REST, procesar configuraciones de infraestructura, y explotar vulnerabilidades en un entorno controlado. Desarrollarás un sistema para detectar desviaciones (drifts) en configuraciones de recursos en la nube y resolverás un desafío CTF para capturar una bandera (flag) en una API aislada.

---

## Resumen del Desafío

El desafío combina dos componentes principales:
1. **Desarrollo de una API REST**: Crearás endpoints para procesar configuraciones actuales de recursos en la nube (por ejemplo, máquinas virtuales, grupos de seguridad), compararlas contra una configuración base, detectar desviaciones (drifts), y resumirlas por tipo o severidad.
2. **CTF de Seguridad en la Nube**: Explotarás una API Flask protegida en una red aislada, forjando un JWT válido para acceder a una bandera.

El entorno incluye:
- Una API Flask con autenticación JWT (RS256).
- Una base de datos PostgreSQL para almacenar usuarios, configuraciones y drifts.
- Una red Docker aislada (sin puertos expuestos directamente).
- Claves RSA para JWT (la clave privada está disponible en un endpoint).
- Redis para caché opcional.
- Archivos JSON con configuraciones base y actuales (en `data/baseline.json` y `data/current.json`).

---

## 🚀 Cómo Configurar el Entorno

1. **Clona el repositorio**:
   ```bash
   git clone <url-del-repositorio>
   cd cloudsec-challenge
   ```

2. **Levanta el entorno**:
   ```bash
   docker-compose up --build -d
   ```
   📌 **Nota**: No verás puertos abiertos. Esto es parte del desafío CTF.

3. **Instala dependencias** (para desarrollo local):
   ```bash
   pip install -r requirements.txt
   ```

---

## 🎯 Pasos del Desafío (en orden)

Sigue estos pasos en el orden indicado para completar el desafío. Cada paso construye sobre el anterior, y el primero es esencial para acceder a la API.

### 1. CTF

**Objetivo**: Exponer la API aislada, forjar un JWT válido y capturar la bandera en el endpoint `/admin/flag`.

**Pasos**:
1. **Conéctate a la red Docker**:
   - La API está en la red `internal` sin puertos expuestos.
   - Usa un proxy (por ejemplo, `nginx`, `socat`) o ejecuta un contenedor intermedio para redirigir el tráfico a la app.
   - Prueba acceder al endpoint `/status` para confirmar la conexión.

2. **Descubre usuarios y roles**:
   - Accede al endpoint `/users` para listar usuarios.
   - Analiza los roles disponibles (pista: busca roles con privilegios elevados).

3. **Forja un JWT válido**:
   - Crea un token JWT firmado con RS256 usando la clave privada.
   - El payload debe tener el formato:
     ```json
     {
       "user": "karim",
       "role": "titular"
     }
     ```

4. **Captura la bandera**:
   - Usa el JWT en el header `Authorization: Bearer <token>` para acceder a `/admin/flag`.
   - Registra la bandera (formato: `FLAG{...}`) como parte de tus entregables.

**Entregables de este paso**:
- Captura de la bandera.
- Script o descripción de cómo expusiste la API y forjaste el JWT.
- Opcional: Sugerencias para mejorar la seguridad de la API (por ejemplo, CORS, rate-limiting).

---

### 2. Mejoras de Desarrollo

**Objetivo**: Desarrollar un módulo para procesar configuraciones de recursos, compararlas contra una base, detectar desviaciones (drifts), y escribir pruebas unitarias/integración.

**Pasos**:
1. **Procesamiento de configuraciones**:
   - Desarrolla funciones/módulos para parsear configuraciones base y actuales (archivos `data/baseline.json` y `data/current.json`).
   - Implementa al menos tres reglas de detección de drift, tales como:
     - **Instance type mismatch**: Detecta si el tipo de instancia de una VM difiere (e.g., `t2.micro` vs. `t2.large`).
     - **Security group rule deviation**: Identifica reglas agregadas, removidas o modificadas (e.g., unexpected open port 22).
     - **Missing or incorrect tags**: Marca recursos que no tienen las etiquetas requeridas (e.g., `environment: production`).
   - Opcional: Usa Redis (incluido en `docker-compose.yml`) para cachear configuraciones y optimizar comparaciones.

2. **Diseño de base de datos**:
   - Usa las tablas `resources_baseline`, `resources_current`, y `drifts` definidas en `db/init.sql`.
   - `resources_baseline` almacena la configuración base, `resources_current` el estado actual, y `drifts` los drifts detectados (resource_id, type, description, severity).
   - Opcional: Agrega índices o constraints para mejorar el rendimiento.

3. **Escribe pruebas**:
   - Crea pruebas unitarias para el procesamiento de configuraciones y reglas de detección.
   - Escribe pruebas de integración para validar la interacción con la base de datos.
   - Incluye al menos un test para validar la firma de JWT.

**Entregables de este paso**:
- Código para el procesamiento de configuraciones y detección de drifts.
- Pruebas unitarias e integración en la carpeta `/tests/`.
- Descripción de cualquier mejora implementada (por ejemplo, caché, índices).

**Ejemplo de configuración base** (`data/baseline.json`):
```json
{
  "resource_id": "vm-001",
  "type": "VM",
  "instance_type": "t2.micro",
  "tags": {"environment": "production", "owner": "team-a"},
  "security_groups": [
    {
      "group_id": "sg-001",
      "rules": [
        {"protocol": "tcp", "port": 80, "source": "0.0.0.0/0"}
      ]
    }
  ]
}
```

**Ejemplo de configuración actual** (`data/current.json`):
```json
{
  "resource_id": "vm-001",
  "type": "VM",
  "instance_type": "t2.large",
  "tags": {"environment": "production"},
  "security_groups": [
    {
      "group_id": "sg-001",
      "rules": [
        {"protocol": "tcp", "port": 80, "source": "0.0.0.0/0"},
        {"protocol": "tcp", "port": 22, "source": "0.0.0.0/0"}
      ]
    }
  ]
}
```

---

### 3. Desarrollo API REST

**Objetivo**: Implementar los endpoints requeridos para procesar configuraciones de recursos y resumir drifts, y extender la funcionalidad de la API.

**Pasos**:
1. **Implementa los endpoints obligatorios**:
   - **POST /resources/ingest**:
     - Recibe el estado actual de recursos en formato JSON.
     - Compara contra la configuración base (en `data/baseline.json` o la tabla `resources_baseline`) y detecta drifts usando las reglas definidas.
     - Almacena los drifts en la tabla `drifts` y el estado actual en `resources_current`.
   - **GET /drifts/summary**:
     - Devuelve un resumen de drifts detectados, agrupados por tipo de recurso o severidad (por ejemplo, `{"VM": 10, "SecurityGroup": 5, ...}`).

2. **Prueba los endpoints**:
   - Usa herramientas como `curl`, Postman o scripts Python para verificar que los endpoints funcionan.
   - Asegúrate de que los errores (por ejemplo, configuraciones mal formadas) sean manejados correctamente.

3. **Opcional: Extiende la API**:
   - Agrega endpoints adicionales, como:
     - **GET /drifts**: Lista drifts con filtros (tipo de recurso, severidad, fecha).
     - **GET /drifts/{drift_id}**: Detalles de un drift específico.
   - Implementa funcionalidades como paginación, ordenamiento o rate-limiting.

**Entregables de este paso**:
- Código de los endpoints en `main.py`.
- Pruebas de integración para los endpoints en `tests/test_api.py`.
- Documentación de los endpoints (por ejemplo, en `docs/api.md`).

---

## Entregables Finales

1. **Repositorio privado en GitHub**:
   - Incluye todo el código, pruebas y documentación.
   - Invita al evaluador al repositorio.

2. **Documentación**:
   - Actualiza este `README.md` con instrucciones para ejecutar tu solución.
   - Agrega un archivo `docs/approach.md` explicando tu enfoque técnico para cada paso.

3. **Docker**:
   - Asegúrate de que la aplicación sea ejecutable con `docker-compose up`.

4. **Captura de la bandera**:
   - Incluye la bandera obtenida en `/admin/flag` en tu documentación.

5. **Pruebas**:
   - Unitarias e integración en la carpeta `/tests/`.

6. **Opcional**:
   - Diagrama de arquitectura en la nube (AWS, GCP, Azure) en `docs/architecture.png`.
   - Despliegue en la nube con instrucciones de acceso.
   - Mejoras de seguridad (CORS, rate-limiting, auditoría de logs).

**¡Mucho éxito!**

---

---

## Solución Implementada

### Resumen de entregables

| Requisito | Estado |
|-----------|--------|
| CTF: exponer API, forjar JWT, capturar flag | ✅ `FLAG{congrats_you_made_it}` |
| Módulo de drift detection (≥ 3 reglas) | ✅ 4 reglas implementadas |
| `POST /resources/ingest` | ✅ |
| `GET /drifts/summary` | ✅ |
| Pruebas unitarias e integración | ✅ 34 tests, 0 fallos |
| `docs/approach.md` | ✅ |
| `docs/api.md` | ✅ |
| `docker-compose up --build` | ✅ |

---

### Requisitos previos

- Docker y Docker Compose
- Python 3.11+ (solo para correr el exploit y los tests fuera del contenedor)

```bash
pip install pyjwt cryptography requests pytest pytest-flask psycopg2-binary
```

---

### 1. Levantar el entorno

```bash
docker-compose up --build -d
```

Tres servicios arrancan en la red interna `challenge-python_internal`:

| Servicio | Imagen | Rol |
|----------|--------|-----|
| `app` | Python 3.11 + gunicorn | API Flask |
| `db` | PostgreSQL 14 | Usuarios, recursos, drifts |
| `redis` | Redis 6 | Caché disponible |

> **Nota**: No hay puertos publicados al host por diseño del CTF.

---

### 2. Exponer la API al host (proxy socat)

Para interactuar con la API desde el host se levanta un contenedor proxy en la misma red interna:

```bash
docker run -d --name proxy \
  --network challenge-python_internal \
  -p 5000:5000 \
  alpine/socat \
  TCP-LISTEN:5000,fork TCP:app:5000
```

Verificar conectividad:

```bash
curl http://localhost:5000/status
```

```json
{"status": "ok"}
```

Listar usuarios:

```bash
curl http://localhost:5000/users
```

```json
{"users": ["alice", "bob", "admin"]}
```

---

### 3. CTF — Captura de la flag

El script automatiza los 6 pasos del exploit:

```bash
python scripts/ctf_exploit.py
```

```
============================================================
  CTF Exploit — challenge-python
  Objetivo: capturar FLAG{...} en /admin/flag
============================================================

[1] Verificando conectividad con http://localhost:5000/status ...
    OK — API accesible: {'status': 'ok'}

[2] Descubriendo usuarios en http://localhost:5000/users ...
    Usuarios encontrados: ['alice', 'bob', 'admin']

[3] Analizando rol requerido desde lógica de main.py ...
    CAMPAING env var : '=MWZzRWdvx2Y'
    Invertida        : 'Y2xvdWRzZWM='
    Base64 decode    : 'cloudsec'
    Rol requerido    : 'cloudsec'

[4] Identificando usuario con rol 'cloudsec' ...
    Usuario objetivo : 'bob' (role='cloudsec' confirmado en init.sql)

[5] Forjando JWT RS256 para user='bob', role='cloudsec' ...
    JWT generado : eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

[6] Capturando flag en http://localhost:5000/admin/flag ...

============================================================
  FLAG CAPTURADA: 🎉 FLAG{congrats_you_made_it}
  Mensaje       : ¡Bien hecho! Descubriste el acceso correcto.
============================================================
```

**Lógica del exploit:**

| Paso | Técnica |
|------|---------|
| Exposición de red | Contenedor socat en red `internal` redirige al host |
| Descubrimiento | `GET /users` lista usuarios de la BD |
| Análisis estático | `CAMPAING = "=MWZzRWdvx2Y"` → invertir → base64 decode → `"cloudsec"` |
| Usuario objetivo | `bob` es el único con `role = "cloudsec"` en `init.sql` |
| Forja de JWT | Clave privada RSA disponible en `app/keys/private_key.pem` |
| Flag | `FLAG{congrats_you_made_it}` |

---

### 4. Drift Detection

#### Ingestar el estado actual

```bash
curl -X POST http://localhost:5000/resources/ingest \
  -H "Content-Type: application/json" \
  -d @data/current.json
```

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

#### Consultar resumen de drifts

```bash
curl http://localhost:5000/drifts/summary
```

```json
{
  "by_type": {"VM": 3, "LoadBalancer": 1},
  "by_severity": {"Critical": 1, "High": 1, "Medium": 1, "Low": 1},
  "total": 4
}
```

#### Reglas implementadas

| # | Regla | Tipo | Severidad |
|---|-------|------|-----------|
| 1 | Cambio de `instance_type` | VM | `High` |
| 2 | Regla de security group agregada | VM | `Critical` |
| 2 | Regla de security group eliminada | VM | `High` |
| 3 | Tag faltante o con valor incorrecto | Todos | `Medium` |
| 4 | Listener de LoadBalancer agregado | LoadBalancer | `Low` |
| 4 | Listener de LoadBalancer eliminado | LoadBalancer | `High` |

---

### 5. Pruebas

```bash
pytest -v
```

```
tests/test_configs.py::test_no_drift_identical_resources PASSED
tests/test_configs.py::test_instance_type_drift PASSED
tests/test_configs.py::test_security_rule_added PASSED
tests/test_configs.py::test_security_rule_removed PASSED
tests/test_configs.py::test_tag_missing PASSED
tests/test_configs.py::test_tag_value_changed PASSED
tests/test_configs.py::test_listener_added PASSED
tests/test_configs.py::test_listener_removed PASSED
tests/test_configs.py::test_new_resource_no_baseline PASSED
tests/test_configs.py::test_missing_resource_in_current PASSED
tests/test_configs.py::test_multiple_drifts_same_resource PASSED
tests/test_configs.py::test_compare_resources_sample_data PASSED
tests/test_jwt.py::test_valid_jwt_grants_access PASSED
tests/test_jwt.py::test_invalid_signature_rejected PASSED
tests/test_jwt.py::test_wrong_algorithm_rejected PASSED
tests/test_jwt.py::test_expired_token_rejected PASSED
tests/test_jwt.py::test_missing_role_claim PASSED
tests/test_jwt.py::test_missing_user_claim PASSED
tests/test_api.py::test_status_ok PASSED
... (16 tests de API)

34 passed in X.XXs
```

**Cobertura por módulo:**

| Archivo de tests | Módulo cubierto | Tests |
|-----------------|-----------------|-------|
| `test_configs.py` | `drift_detector.py` — 4 reglas de negocio | 12 |
| `test_jwt.py` | `main.py` — autenticación RS256 | 6 |
| `test_api.py` | `main.py` — todos los endpoints | 16 |

---

### 6. Estructura del proyecto

```
challenge-python/
├── app/
│   ├── Dockerfile
│   ├── main.py              # API Flask (5 endpoints)
│   ├── drift_detector.py    # Motor de drift detection
│   ├── requirements.txt
│   └── keys/
│       ├── private_key.pem  # Firma JWT (RS256)
│       └── public_key.pem   # Verificación JWT
├── data/
│   ├── baseline.json        # Configuración base (seed)
│   └── current.json         # Estado actual (input de ingest)
├── db/
│   └── init.sql             # Esquema + usuarios iniciales
├── docs/
│   ├── approach.md          # Enfoque técnico detallado
│   └── api.md               # Documentación de endpoints
├── scripts/
│   └── ctf_exploit.py       # Exploit automatizado (6 pasos)
├── tests/
│   ├── conftest.py          # Fixtures y mocks
│   ├── test_configs.py      # Tests unitarios drift engine
│   ├── test_jwt.py          # Tests de autenticación JWT
│   └── test_api.py          # Tests de integración API
├── docker-compose.yml
└── pytest.ini
```

---

### 7. Limpieza

```bash
docker-compose down
docker rm -f proxy
```