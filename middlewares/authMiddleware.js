//  Controlador de Seguridad, protege rutas solo para los usuarios que 
// hayan iniciado sesion puedan acceder
const jwt = require("jsonwebtoken");

exports.verifySession = (req,res, next) => {
    if (req.session?.user) return next();
    res.status(401).send("No autenticado");

};

exports.verifyJWT =  (req,res,next) => {
    const header = req.headers.authorization;
    if (!header) return res.status(401).send("Token no encontrado");
    const token = header.split(" ")[1];
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    }catch{
        res.status(403).send("Token Invalido");

    }

};