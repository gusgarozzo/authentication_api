# Auth API

API de autenticación de usuarios construida con NestJS, TypeORM y SQLite.

## Descripción

Esta API proporciona un sistema de autenticación de usuarios que incluye registro, inicio de sesión y protección de rutas mediante JSON Web Tokens (JWT).

## Tecnologías Utilizadas

- **Framework:** [NestJS](https://nestjs.com/)
- **Base de Datos:** [SQLite](https://www.sqlite.org/index.html)
- **ORM:** [TypeORM](https://typeorm.io/)
- **Autenticación:** [Passport](http://www.passportjs.org/) con estrategias [JWT](https://github.com/mikenicholson/passport-jwt) y [Local](https://github.com/jaredhanson/passport-local)
- **Validación:** [class-validator](https://github.com/typestack/class-validator) y [class-transformer](https://github.com/typestack/class-transformer)
- **Lenguaje:** [TypeScript](https://www.typescriptlang.org/)

## Alcances del Desarrollo

- Registro de nuevos usuarios.
- Inicio de sesión y generación de tokens de acceso.
- Protección de rutas mediante guardias de autenticación.
- Validación de datos de entrada.
- Estructura de proyecto modular y escalable.

## Instalación

1. Clona el repositorio:
   ```bash
   git clone https://github.com/tu-usuario/auth-api.git
   ```
2. Instala las dependencias:
   ```bash
   npm install
   ```

## Uso

1. Inicia la aplicación en modo de desarrollo:
   ```bash
   npm run start:dev
   ```
2. La API estará disponible en `http://localhost:3000`.

## Endpoints

- `POST /auth/register`: Registro de un nuevo usuario.
- `POST /auth/login`: Inicio de sesión de un usuario.
- `GET /profile`: Ruta protegida que devuelve el perfil del usuario autenticado.

## Autenticación

La autenticación se realiza mediante JSON Web Tokens (JWT). Para acceder a las rutas protegidas, debes incluir el token de acceso en el encabezado `Authorization` de la siguiente manera:

```
Authorization: Bearer <token>
```

## Base de Datos

La base de datos utilizada es SQLite. El archivo de la base de datos se encuentra en `data/db.sqlite`

## En Desarrollo

- Roles de usuario
- Posibilidad de añadir ávatar al usuario (URL de imagen o file -> Upload de la img a una instancia AWS S3 para obtener la URL)
- Test unitarios
- Swagger