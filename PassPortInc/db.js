const sqlite3 = require("sqlite3").verbose(); // Activa mensajes si ocurre un error o advertencia

const db = new sqlite3.Database("./database/passport.db");

db.inicialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password TEXT,
        rol TEXT DEFAULT 'usuario'
        )`);
});
module.exports = db;