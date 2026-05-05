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