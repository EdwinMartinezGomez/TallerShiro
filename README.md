# TallerShiro

Resumen
-------
TallerShiro es una aplicación ejemplo en Spring Boot que integra Apache Shiro para
autenticación, autorización y manejo de sesiones. El propósito es practicar:
- Autenticación con contraseñas hasheadas (BCrypt/Argon2)
- Autorización basada en roles y permisos (anotaciones `@RequiresRoles` / `@RequiresPermissions`)
- Manejo de sesiones web (JSESSIONID y asociación Subject ↔ HttpSession)
- Endurecimiento de hashing (comparación de parámetros y benchmarking)

Estructura del proyecto
-----------------------
- `src/main/java/co/edu/uptc/TallerShiro/`
	- `TallerShiroApplication.java` — clase principal Spring Boot.
	- `config/`\
		- `ShiroConfiguration.java` — beans de Shiro (SecurityManager, realms, filtros, soporte de anotaciones).
		- `DatabaseRealm.java` — Realm personalizado que autentica contra la BD (UserRepository) y provee roles/permiso.
		- `DataInitializer.java` — crea usuarios demo con hashes.
		- `SessionSubjectFilter.java` — filtro auxiliar que reconstruye un `Subject` desde la `HttpSession` cuando sea necesario.
		- `GlobalExceptionHandler.java` — manejo conciso de errores de Shiro (Unauthenticated/Authorization)
	- `controller/`\
		- `AuthenticationController.java` — login, registro y logout (invalida `HttpSession` al salir).
		- `ProductController.java` — CRUD de `Product` (métodos protegidos con `@RequiresPermissions`).
		- `InfoController.java` — páginas de administración protegidas por roles.
		- `DebugController.java` — endpoint `/debug/subject` para inspeccionar principal, sesiones y cookies.
		- `SecurityDemoController.java` — endpoint `/security/hash/compare` para comparar tiempos de hashing.
	- `model/` — entidades `User`, `Product`.
	- `repository/` — JPA repositories.
	- `services/` — servicios de negocio y sus implementaciones.
	- `util/PasswordHashingUtil.java` — utilitario de hashing: BCrypt (configurable), Argon2 (configurable), SHA-512 salteado, timing/benchmark helpers.

 - `src/main/resources/`
	- `application.properties` — configuración (H2, logging, shiro.realm.type).
	- `shiro.ini` — (opcional) archivo ini; el proyecto usa `DatabaseRealm` por defecto.
	- `templates/` — vistas Thymeleaf (login, register, products, session-info, error).

Funcionamiento resumido
-----------------------
1. Registro/Login
	 - `AuthenticationController` usa `PasswordHashingUtil` para generar/verificar hashes.
	 - Al hacer login se crea la `HttpSession` antes de `Subject.login(...)` y se guarda `username`.
	 - `SessionSubjectFilter` puede reconstruir un `Subject` por petición desde `HttpSession` si hace falta.

2. Autorización
	 - `DatabaseRealm` asigna roles (`admin`, `seller`, `user`) y permisos (`product:create/read/update/delete`, `user:view/manage`, `session:view`).
	 - Rutas y métodos se protegen usando el `ShiroFilterFactoryBean` (filter chain) y anotaciones `@RequiresPermissions` / `@RequiresRoles`.

3. Sesiones y logout
	 - Se usa `ServletContainerSessionManager` para mapear Shiro ↔ `HttpSession` (JSESSIONID).
	 - En logout `Subject.logout()` y `HttpSession.invalidate()` se ejecutan; `username` se remueve para evitar reconstrucción.

Endpoints útiles
----------------
- `GET /login`, `POST /login` — formulario y procesamiento.
- `GET /logout` — cierra sesión e invalida `HttpSession`.
- `GET /products/list` — lista protegida por permiso `product:read`.
- `GET /debug/subject` — devuelve JSON con `principal`, `isAuthenticated`, `shiroSessionId`, `servletSessionId`, cookies y headers (útil para debugging).
- `GET /security/hash/compare?pwd=...` — comparador/benchmark local de hashing (bcrypt/argon2/sha512).

Cómo ejecutar
-------------
Requisitos: Java 17+, Maven

Desde la raíz del proyecto en Windows `cmd.exe`:

```bash
mvn -q spring-boot:run
```

O para ejecutar los tests:

```bash
mvn -Dtest=AuthFlowIntegrationTest test
```

Comprobaciones rápidas con `curl` (ejecutar en `cmd.exe` con las comillas correctas):

- Login (guardar cookies):
```bash
curl -v -c cookies.txt -d "username=user1&password=password123" -X POST http://localhost:8080/login -L
```
- Consultar debug con la cookie grabada:
```bash
curl -v -b cookies.txt http://localhost:8080/debug/subject
```
- Comparar hashing:
```bash
curl http://localhost:8080/security/hash/compare?pwd=MiPassword
```

Workflow de construcción 
----------------------------------
A continuación se incluye el workflow de construcción y entrega solicitado, que describe las partes del taller y qué comprobar en cada una:

Parte 1 — Construcción de la Aplicación Base (Sin Seguridad)
- Abordaje: Se implementó un CRUD mínimo para `Product` usando Spring Boot, Spring MVC, Thymeleaf y Spring Data JPA. Las operaciones CRUD (crear, leer, actualizar, eliminar) están en `ProductController`, la entidad en `model/Product.java`, y el repositorio en `repository/ProductRepository.java`. El proyecto arranca sin seguridad habilitada por defecto gracias a rutas `anon` en la configuración de filtros.

Parte 2 — Integración de Apache Shiro
- Abordaje: Se añadió la configuración de Shiro en `config/ShiroConfiguration.java`. Se registra un `SecurityManager` (con `DatabaseRealm`) y se define un `ShiroFilterFactoryBean` con la `filterChainDefinitionMap` para declarar qué rutas son públicas y cuáles requieren `authc`, `roles[...]` o `perms[...]`. Se habilitó soporte para anotaciones (`DefaultAdvisorAutoProxyCreator`, `AuthorizationAttributeSourceAdvisor`) para usar `@Requires*` en controladores.

Parte 3 — Autenticación (Login Seguro)
- Abordaje: La autenticación usa un `DatabaseRealm` (`config/DatabaseRealm.java`) que consulta `UserRepository`. Las contraseñas se generan/validan con `util/PasswordHashingUtil.java` (soporta BCrypt y Argon2, con métodos parametrizables). El controlador `AuthenticationController` realiza `Subject.login()` y crea la `HttpSession` antes del login para asegurar que el contenedor asigne `JSESSIONID`.

Parte 4 — Autorización con Roles y Permisos
- Abordaje: Se definieron roles (`admin`, `seller`, `user`) y permisos (`product:create/read/update/delete`, `user:view/manage`, `session:view`) en `DatabaseRealm#doGetAuthorizationInfo`. Se protegieron rutas con la `filterChainDefinitionMap` (`perms[...]`, `roles[...]`) y se usaron anotaciones `@RequiresPermissions` en `ProductController` y `@RequiresRoles` en `InfoController` para protección a nivel de método.

Parte 5 — Manejo de Sesiones con Shiro
- Abordaje: Se eligió usar `ServletContainerSessionManager` (configurado en `ShiroConfiguration`) para mapear la sesión de Shiro al `HttpSession` del contenedor. En `AuthenticationController` se crea la `HttpSession` antes del login y se guarda `username` en la sesión. Se añadió `DebugController` (`/debug/subject`) para inspeccionar `principal`, estado de autenticación y `servletSessionId`. Para robustecer la reconstrucción de identidad en peticiones, se creó `SessionSubjectFilter` que, si encuentra `username` en la `HttpSession`, sintetiza un `Subject` por petición. El logout llama `Subject.logout()` y `HttpSession.invalidate()`.

Parte 6 — Criptografía Avanzada y Endurecimiento
- Abordaje: `PasswordHashingUtil` fue ampliado para soportar parámetros configurables de BCrypt y Argon2 y para medir tiempos de hashing (`measureHashTimeMillis`). Se añadió `SecurityDemoController` con `/security/hash/compare` para comparar tiempos entre configuraciones débiles y fuertes (útil para elegir parámetros de cost/iteraciones/memoria en la máquina objetivo).

Recomendaciones de seguridad
-------------------------------------
- Preferir Argon2 para nuevas aplicaciones; usar parámetros de memoria/iteraciones adecuados (ej. iter=3, mem=131072 KB ~128MB) si el servidor puede asumir el coste.
- Si se usa BCrypt, emplear cost (log rounds) >= 12–14 según la latencia aceptable.
- Almacenar el algoritmo y parámetros junto al hash en la base de datos para poder migrar y verificar correctamente.
- Evitar algoritmos rápidos (p. ej. SHA-512 puro) para hashing de contraseñas; pueden usarse para HMAC o integridad con sal.


Parte 7 — Pruebas Integrales y Documentación Final
- Abordaje: Se añadió un test de integración `AuthFlowIntegrationTest` (MockMvc) que automatiza: login → mantener sesión → acceder a página protegida → logout → verificar que la ruta protegida ya no es accesible. Además se generó este `README.md` con el workflow y se documentaron los pasos para crear la evidencia en video.


Pruebas y evidencia 
-----------------------------
Workflow sugerido para la prueba final y para generar evidencia en video:
1. Iniciar la aplicación (`mvn spring-boot:run`).
2. Abrir `/security/hash/compare` para mostrar timings con los parámetros que elijes (grabar esta comparación).
3. En la UI, registrar o usar `user1/password123` (creados por `DataInitializer`).
4. Mostrar `/debug/subject` inmediatamente después del login para probar `principal` y `servletSessionId`.
5. Acceder a `/products/list` para demostrar autorización.
6. Hacer logout y volver a intentar `/products/list` para confirmar que la sesión fue invalidada.
7. Guardar los logs de consola (muestran prints `[Auth] HttpSession id` y verificación de hashes).
8. Compilar pequeño vídeo donde expliques los pasos y muestres las pruebas en pantalla.

Notas y decisiones importantes
- `SessionSubjectFilter` es una solución pragmática para garantizar que las anotaciones de Shiro vean una identidad en cada petición si la integración web no estaba ligando el Subject al `HttpSession` en el entorno actual. En un entorno productivo se preferiría resolver la raíz (usar una versión de Shiro completamente compatible con Jakarta o registrar correctamente el Shiro web filter) en vez de depender de la reconstrucción manual.
- Se eligió `DatabaseRealm` para autenticación realista con contraseñas hasheadas almacenadas en la BD (DataInitializer crea usuarios demo). El `shiro.ini` se mantiene para referencia, pero la configuración principal usa el realm personalizado.


