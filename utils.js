import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

export const SECRET_KEY = process.env.SECRET_KEY || 'dev_secret';
export const PORT = process.env.PORT || 3000;


// Funciones de Hashing
export const hashing = (password) => {
    return bcrypt.hashSync(password, 10); // 10-> costo, numero de rondas que bcrypt usa para aplicar el algoritmo de encriptacion
};

export const validar_password = (plainPassword, hashedPassword) => {
    return bcrypt.compareSync(plainPassword, hashedPassword);
};

// --- Middlewares de Autenticación ---

// 1. Verifica si el usuario está logueado (tiene token válido)
export const authMiddleware = (req, res, next) => {
    const token = req.cookies.access_token; // Verifica si trae la cookie
    
    if (!token) {
        return res.status(403).redirect('/'); 
    }

    try {
        const decoded = jwt.verify(token, SECRET_KEY); // Verifica si la firma es valida
        req.user = decoded; // Si todo esta bien, deja pasar y anota quien eres en req.user
        next();
    } catch (err) {
        // Token manipulado o expirado
        res.clearCookie('access_token');
        return res.status(401).redirect('/');
    }
};

// 2. RBAC: Verifica si el usuario tiene el rol necesario
export const requireRole = (...allowedRoles) => { // Zona VIP, Si intentas entrar a /admin pero tu rol es user , te detiene en seco
    return (req, res, next) => {
        if (!req.user || !allowedRoles.includes(req.user.role)) {
            return res.status(403).send(`
                <h1>Acceso Denegado 🚫</h1>
                <p>No tienes los permisos de nivel: ${allowedRoles.join(' o ')}</p>
                <a href="/">Volver</a>
            `);
        }
        next();
    };
};