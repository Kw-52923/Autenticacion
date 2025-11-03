// Maneja Registro,inicio y cierre de sesion de los usuarios 

const bcrypt = require("bcrypt"); 
const jwt = require("jsonwebtoken");
const db = require("../db");

exports.register = async (req,res) => {
    const { email, password} = req.body;
    const hashed = await bcrypt.hash(password, 10)


db.run("INSERT INTO usuarios (email, password) VALUES (?,?)", [email, hashed], (err) => {
   if (err) return res.status(400).send("Usuario ya existe");
   res.send("Registro exitoso. Ahora puedes iniciar sesión.");

});
};

exports.login = async (req,res) => {
    const {email, password, tipo } = req.body; // tipo = "cookie" o "jwt"

    db.get("SELECT * FROM usuarios WHERE email=?", [email], async (err,user) => {
        if (err) return res.status(404).send("Usuario no encontrado");
        const match = await bcrypt.compare(password,user.password);
        if (!match) return res.status(403).send("Contraseña incorrecta");

        if (tipo === "cookie") {
            req.session.user = { id: user.id, rol: user.rol};
            res.send("Sesion iniciada con cookie");
        }else{
            const token= jwt.sign({ id: user.id, rol: user.rol}, process.env.JWT_SECRET, { expiresIn: "1h" });
            res.json({ token });
        }
    });

};

exports.logout = (req,res) => {
    req.session.destroy(() => res.clearCookie("connect.sid").send("Sesion cerrada"));  
};