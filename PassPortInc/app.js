const express = require("express"); // Importa libreria Express, facilita crear un servidor web en node.js
const session = require("express-session"); // Importa libreria para manejar sesiones (datos guardados entre peticiones de un mismo usuario)
const cookieParser = require("cookie-parser"); //Permite leer las cookies que el navegador envia en la peticion 
const helmet = require("helmet"); // Añade cabeceras HTTP que ayuda a proteger la app de ataques comunes
const csurf = require("csurf"); // Libreria para proteccion contra CSRF (Cross-Site Request Forgery)
const path = require("path"); // Modulo nativo de Node para trabajar con rutas de archivos (carpetas)
require("dotenv").config(); // Carga variables de entorno desde .env  al process.env

// Rutas Importadas
const authRoutes = require("./routes/auth");
const userRoutes = require("./routes/user");
const adminRoutes = require("./routes/admin");

// Crea la aplicacion Express- el "servidor" sobre el cual se aplicara middlewares y rutas
const app = express();

// Middlewares
app.use(helmet()); // Aplica como middleware global- todas las peticiones pasaran por Helmet
app.use(express.urlencoded({ extended: true }));// Permite que Express entienda los cuerpos de peticiones (formularios HTML)
app.use(express.json()); // Convierte cuerpos JSON en req.body
app.use(cookieParser()); // Coloca en req.cookies las cookies que viene de la peticion, ya parseada 
app.use(express.static("public")); // Sirve archivos estaticos (CSS,JS del cliente,img) dentro de la carpeta public

//Configuracion de sesiones
app.use(session({
  secret: process.env.SESSION_SECRET, // secret -> cadena usada para firmar la cookie de sesion. Se guarda en .env
  resave: false, // Evita reescribir la sesion en el store si no cambió
  saveUninitialized: false, // Evita crear sesiones vaciaspara visitantes que no inician sesion o no usan sesiones
  cookie: {
    httpOnly: true, // Evita que JS en el navegador lea la cookie (protege contra XSS)
    secure: false, // la cookie de sesión se enviará tanto por HTTP como por HTTPS
    sameSite: "strict" // La cookie solo se envia si la peticion viene del mismo sitio -- mas proteccion contra CSRF
  }
}));
// indica que se usara  EJS como motor de plantilla
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views")); // Le indica a express donde estan las plantillas EJS, dirname: indica la carpeta donde esta app.js

// Registro de rutas
app.use("/auth", authRoutes);
app.use("/user", userRoutes);
app.use("/admin", adminRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor en puerto ${PORT}`));
