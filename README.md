# 🔐 PassPort Inc. - Sistema de Autenticación Seguro

Sistema de autenticación y gestión de sesiones desarrollado para PassPort Inc., una plataforma de gestión de identidad digital.

## 🎯 Descripción

Implementación completa de un sistema de autenticación que permite a los usuarios registrarse, iniciar sesión y gestionar sus sesiones de forma segura, con opciones tanto de sesiones persistentes (cookies) como sin estado (JWT).

## ✨ Características Principales

- **Registro y Login**: Autenticación con email y contraseña
- **Hashing Seguro**: Contraseñas protegidas con bcrypt
- **Doble Sistema de Sesiones**:
  - Sesiones persistentes con cookies seguras
  - Sesiones sin estado con JWT
- **Control de Acceso (RBAC)**: Roles de Usuario y Administrador
- **Protección de Seguridad**:
  - Prevención XSS y CSRF
  - Protección contra fuerza bruta
  - Cookies con flags `HTTP-only` y `Secure`

## 🛠️ Tecnologías

**Backend:**
- Node.js  (ES Modules)
- Express - Framework web
- better-sqlite3 - Base de datos SQLite
- EJS - Motor de plantillas

**Autenticación:**
- bcrypt  - Hashing de contraseñas con 10 salt rounds
- jsonwebtoken  - Tokens JWT firmados
- cookie-parser  - Manejo de cookies HTTP-only

**Seguridad:**
- helmet  - Headers de seguridad HTTP
- csurf - Protección CSRF con tokens
- express-validator - Validación y sanitización de inputs
- dotenv  - Variables de entorno

**Control de Acceso:**
- Sistema RBAC (Role-Based Access Control) personalizado
- Rate limiting en memoria para prevenir fuerza bruta (3 intentos, 2 min bloqueo)

## 🔑 Variables de Entorno

Crea un archivo `.env` en la raíz del proyecto con las siguientes variables:

```env
SECRET_KEY=mi_super_clave_123
PORT=3000
```

**Importante:** 
- `SECRET_KEY`: Clave secreta para firmar los JWT. **Cambia este valor en producción** por una clave más segura y aleatoria.
- `PORT`: Puerto en el que correrá el servidor (por defecto 3000)
- `NODE_ENV`: Opcional, se usa para activar cookies `Secure` en producción

## 📋 Endpoints Principales

### Autenticación
- `POST /register` - Registro de usuario (email + contraseña mín. 8 caracteres)
- `POST /login` - Inicio de sesión (genera JWT en cookie HTTP-only)
- `POST /logout` - Cerrar sesión (elimina cookie)

### Rutas Protegidas
- `GET /protected` - Área protegida (requiere autenticación)
- `GET /admin` - Panel de administración (requiere rol admin)
- `POST /admin/promote` - Promover usuario a admin (solo admins)

## 🔒 Seguridad Implementada

- ✅ **Hashing de contraseñas**: bcrypt con 10 salt rounds
- ✅ **Tokens JWT**: Firmados con clave secreta, expiración 1h
- ✅ **Cookies seguras**: HTTP-only, Secure (en producción), SameSite=strict
- ✅ **Protección CSRF**: Tokens únicos en cada formulario
- ✅ **Validación de inputs**: express-validator con sanitización
- ✅ **Rate limiting**: Bloqueo tras 3 intentos fallidos (2 min)
- ✅ **Headers de seguridad**: Helmet.js
- ✅ **SQL Injection**: Prepared statements con better-sqlite3
- ✅ **XSS**: Sanitización de inputs y escape de HTML en EJS

## 👥 Roles y Permisos

| Rol | Permisos |
|-----|----------|
| Usuario | Acceso a datos propios |
| Administrador | Acceso completo + gestión de usuarios |

## 📝 Uso

### Registro de Usuario
1. Accede a `http://localhost:3000`
2. Completa el formulario de registro con email y contraseña (mín. 8 caracteres)
3. El sistema hasheará tu contraseña con bcrypt

### Inicio de Sesión
1. Ingresa tu email y contraseña
2. Si las credenciales son correctas, recibirás un JWT en una cookie HTTP-only
3. Serás redirigido a la página principal con tu sesión activa

### Acceso a Rutas Protegidas
- **`/protected`**: Accesible por cualquier usuario autenticado
- **`/admin`**: Solo accesible por usuarios con rol "admin"
- Los middlewares `authMiddleware` y `requireRole` verifican automáticamente los permisos

### Promoción de Usuarios (Admin)
Los administradores pueden promover usuarios regulares a admin desde el panel `/admin`

### Protección contra Fuerza Bruta
- Después de 3 intentos fallidos, la cuenta se bloquea por 2 minutos
- El sistema mantiene un registro en memoria de intentos por email

## 🎯 Características Destacadas

### Sistema RBAC Personalizado
- Dos roles: `user` (usuario regular) y `admin` (administrador)
- Middleware `requireRole()` flexible que acepta múltiples roles
- Los admins pueden promover usuarios desde el panel

### Autenticación Dual
- **JWT en cookies**: Autenticación sin estado con tokens firmados
- **Sesión persistente**: Cookie con duración de 1 hora, renovable

### Base de Datos Segura
- SQLite con mejor rendimiento (better-sqlite3)
- Prepared statements para prevenir SQL injection
- Esquema simple: `users(id, email, password, role)`

### Control de Fuerza Bruta Inteligente
- Bloqueo por email (no por IP) para evitar DoS
- Sistema en memoria con reinicio automático tras login exitoso
- Tiempo de bloqueo configurable
