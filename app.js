// Importaciones 
import express from 'express'; // Framework para crear app web
import cookieParser from 'cookie-parser'; // Para leer las cookies que envia el navegador
import protectorDeAtaques from 'csurf'; // Para proteccion contra ataques CSRF 
import helmet from 'helmet'; // Para proteccion contra ataques XSS u otras vulnerabilidades 
import jwt from 'jsonwebtoken';
import { body, validationResult } from 'express-validator'; // Body, creador de reglas, validationResult arbitro, verifica que las reglas se cumplan
import path from 'path';
import { fileURLToPath } from 'url'; // file://, traduce la url en una ruta normal del S.O para luego usar el path
import dotenv from 'dotenv';
dotenv.config();
//console.log("SECRET_KEY cargada:", SECRET_KEY);
import { PORT, SECRET_KEY } from './utils.js'; 
import { hashing, validar_password, authMiddleware, requireRole } from './utils.js';
import { createUser, getUserByEmail, setUserRole } from './init_db.js';

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// --- Configuración de Seguridad y Middleware ---
app.use(helmet({
    contentSecurityPolicy: false, // Desactivado solo para facilitar estilos inline en este demo
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Configuración de EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Protección CSRF (Debe ir después de cookie parser y body parser)
const miEscudo = protectorDeAtaques({ cookie: true }); // Usamos cookie para el secret del CSRF
app.use(miEscudo);

// --- Control de Fuerza Bruta (En Memoria) ---
const loginAttempts = {};
const MAX_ATTEMPTS = 3; //Si falla 3 veces, bloquea el email por 2 minutos
const LOCK_TIME = 2 * 60 * 1000; // 2 minutos

// --- Rutas ---

// Muestra la pagina inicial, detecta si hay token valido
app.get('/', (req, res) => {
    const token = req.cookies.access_token;
    let user = null;

    if (token) {
        try {
            user = jwt.verify(token, SECRET_KEY);
        } catch (e) {
            // Token invalido o expirado, limpiamos
            res.clearCookie('access_token');
        }
    }

    res.render('index', { 
        user, 
        msg: null, 
        error: null, 
        csrfToken: req.csrfToken() 
    });
});

// Registro, valida email y contraseña , crea un usuario en la BD
app.post('/register', 
    [
        body('email').isEmail().normalizeEmail(), // Asegura que no envien basura 
        body('password').isLength({ min: 8 }).withMessage('La contraseña debe tener al menos 8 caracteres')
    ],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).render('index', { user: null, msg: null, error: errors.array()[0].msg, csrfToken: req.csrfToken() });
        }

        const { email, password } = req.body;

        try {
            const existing = getUserByEmail(email);
            if (existing) {
                return res.status(409).render('index', { user: null, msg: null, error: 'El usuario ya existe', csrfToken: req.csrfToken() });
            }

            const hashedPassword = hashing(password);
            // El primer usuario creado será admin automágicamente para facilitar pruebas, los siguientes 'user'
            // Esto es lógica de negocio opcional, pero útil para testear RBAC
            const role = 'user'; 
            
            createUser(email, hashedPassword, role);
            
            return res.status(201).render('index', { user: null, msg: 'Usuario registrado. Por favor inicia sesión.', error: null, csrfToken: req.csrfToken() });
        } catch (err) {
            console.error(err);
            return res.status(500).render('index', { user: null, msg: null, error: 'Error interno del servidor', csrfToken: req.csrfToken() });
        }
    }
);

// Login,valida credenciales, aplica fuerza bruta, genera JWT, lo guarda en cookie segura
app.post('/login', 
    [body('email').isEmail().normalizeEmail(), body('password').exists()],
    (req, res) => {
        const { email, password } = req.body;
        
        // 1. Verificar Bloqueo. El usuario intento entrar 3 veces mal antes? Si, ¡Fuera!
        if (loginAttempts[email] && loginAttempts[email].lockedUntil > Date.now()) {
            const remaining = Math.ceil((loginAttempts[email].lockedUntil - Date.now()) / 1000);
            return res.status(429).render('index', { user: null, msg: null, error: `Cuenta bloqueada temporalmente. Espera ${remaining} segundos.`, csrfToken: req.csrfToken() });
        }

        const user = getUserByEmail(email); // Busca el usuario en la BD

        // 2.
        if (!user || !validar_password(password, user.password)) {
            // Lógica de intentos fallidos
            if (!loginAttempts[email]) loginAttempts[email] = { count: 0, lockedUntil: 0 };
            loginAttempts[email].count++;

            if (loginAttempts[email].count >= MAX_ATTEMPTS) {
                loginAttempts[email].lockedUntil = Date.now() + LOCK_TIME;
                return res.status(429).render('index', { user: null, msg: null, error: 'Demasiados intentos fallidos. Cuenta bloqueada temporalmente.', csrfToken: req.csrfToken() });
            }

            return res.status(401).render('index', { user: null, msg: null, error: 'Credenciales inválidas', csrfToken: req.csrfToken() });
        }

        // 3. Éxito: Resetear intentos y generar JWT
        delete loginAttempts[email];

        // Genera el JWT, Encriptación de datos sensibles: NO guardamos info personal sensible, solo ID y Rol.
        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role }, 
            SECRET_KEY, 
            { expiresIn: '1h' }
        );

        // Guardar JWT en Cookie HTTP-Only (Seguridad Esencial)
        res.cookie('access_token', token, {
            httpOnly: true, // JS no puede leerlo
            secure: process.env.NODE_ENV === 'production', // True en prod
            sameSite: 'strict',
            maxAge: 3600000 // 1 hora
        });

        res.redirect('/');
    }
);

// Logout,limpia cookie
app.post('/logout', (req, res) => {
    res.clearCookie('access_token');
    res.redirect('/');
});

// --- Rutas Protegidas y RBAC ---

// Zona Protegida (Solo usuario logueado)
app.get('/protected', authMiddleware, (req, res) => {
    res.render('protected', { user: req.user, csrfToken: req.csrfToken() });
});

// Zona Admin (Solo rol 'admin')
app.get('/admin', authMiddleware, requireRole('admin'), (req, res) => {
    res.render('admin', { user: req.user, csrfToken: req.csrfToken(), msg: null });
});

// Acción Admin: Promover usuario
app.post('/admin/promote', authMiddleware, requireRole('admin'), (req, res) => {
    const { targetEmail } = req.body;
    try {
        const changed = setUserRole(targetEmail, 'admin');
        if(changed.changes > 0) {
            res.render('admin', { user: req.user, csrfToken: req.csrfToken(), msg: `Usuario ${targetEmail} ahora es Admin.` });
        } else {
            res.render('admin', { user: req.user, csrfToken: req.csrfToken(), msg: `Usuario no encontrado.` });
        }
    } catch (err) {
        res.status(500).send("Error de base de datos");
    }
});

// Manejo de errores CSRF
app.use((err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') {
        return res.status(403).render('index', { user: null, msg: null, error: 'Sesión o Token CSRF inválido. Recarga la página.', csrfToken: 'invalid' });
    }
    next(err);
});

app.listen(PORT, () => {
    console.log(`🔒 PassPort Secure Server corriendo en http://localhost:${PORT}`);
});