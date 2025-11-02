const sqlite3 = require("sqlite3").verbose();

const db = new sqlite3.Database("./database/passport.db");

db.inicialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password TEXT,
        )`)
})