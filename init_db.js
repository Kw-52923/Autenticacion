import Database from 'better-sqlite3';

// Inicialización de DB
const db = new Database('passport.db');


// Usamos 'users' consistentemente
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user'
    )
`);

// Consultas Preparadas (Prepared Statements para evitar SQL Injection)

function createUser(email, hashedPassword, role) {
    const stmt = db.prepare("INSERT INTO users (email, password, role) VALUES (?, ?, ?)");
    return stmt.run(email, hashedPassword, role);
}

function getUserByEmail(email) {
    // Devuelve el objeto usuario o undefined
    const stmt = db.prepare("SELECT * FROM users WHERE email = ?");
    return stmt.get(email);
}

function setUserRole(email, newRole) {
    const stmt = db.prepare("UPDATE users SET role = ? WHERE email = ?");
    return stmt.run(newRole, email);
}

export {
    db,
    createUser,
    getUserByEmail,
    setUserRole
};