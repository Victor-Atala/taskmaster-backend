const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'taskmaster_secret_2024';

app.use(cors());
app.use(express.json());

const db = new sqlite3.Database(path.join(__dirname, 'taskmaster.db'));

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL, createdAt TEXT DEFAULT (datetime('now')))`);
  db.run(`CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT, userId INTEGER NOT NULL,
    title TEXT NOT NULL, description TEXT DEFAULT '',
    priority TEXT DEFAULT 'MEDIUM', category TEXT DEFAULT 'General',
    completed INTEGER DEFAULT 0,
    createdAt TEXT DEFAULT (datetime('now')), updatedAt TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (userId) REFERENCES users(id))`);
});

function fmt(t) { return { ...t, completed: t.completed === 1 }; }

function auth(req, res, next) {
  const h = req.headers['authorization'];
  if (!h) return res.status(401).json({ error: 'Token requerido' });
  const token = h.startsWith('Bearer ') ? h.slice(7) : h;
  try { req.userId = jwt.verify(token, JWT_SECRET).userId; next(); }
  catch { res.status(401).json({ error: 'Token invalido' }); }
}

app.post('/api/v1/auth/register', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Campos requeridos' });
  db.get('SELECT id FROM users WHERE email=?', [email], (e, row) => {
    if (row) return res.status(409).json({ error: 'Email ya registrado' });
    const hashed = bcrypt.hashSync(password, 10);
    db.run('INSERT INTO users (name,email,password) VALUES(?,?,?)', [name,email,hashed], function(e) {
      if (e) return res.status(500).json({ error: e.message });
      const token = jwt.sign({ userId: this.lastID }, JWT_SECRET, { expiresIn: '7d' });
      res.status(201).json({ token, user: { id: this.lastID, name, email } });
    });
  });
});

app.post('/api/v1/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Campos requeridos' });
  db.get('SELECT * FROM users WHERE email=?', [email], (e, user) => {
    if (!user || !bcrypt.compareSync(password, user.password))
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
  });
});

app.get('/api/v1/tasks', auth, (req, res) => {
  let q = 'SELECT * FROM tasks WHERE userId=?'; const p = [req.userId];
  if (req.query.completed !== undefined) { q += ' AND completed=?'; p.push(req.query.completed==='true'?1:0); }
  if (req.query.category) { q += ' AND category=?'; p.push(req.query.category); }
  q += ' ORDER BY createdAt DESC';
  db.all(q, p, (e, rows) => { if(e) return res.status(500).json({error:e.message}); res.json(rows.map(fmt)); });
});

app.post('/api/v1/tasks', auth, (req, res) => {
  const { title, description='', priority='MEDIUM', category='General' } = req.body;
  if (!title) return res.status(400).json({ error: 'Titulo requerido' });
  db.run('INSERT INTO tasks (userId,title,description,priority,category) VALUES(?,?,?,?,?)',
    [req.userId,title,description,priority,category], function(e) {
      if(e) return res.status(500).json({error:e.message});
      db.get('SELECT * FROM tasks WHERE id=?',[this.lastID],(e,t)=>res.status(201).json(fmt(t)));
    });
});

app.put('/api/v1/tasks/:id', auth, (req, res) => {
  const {id}=req.params;
  db.get('SELECT * FROM tasks WHERE id=? AND userId=?',[id,req.userId],(e,task)=>{
    if(!task) return res.status(404).json({error:'No encontrada'});
    const {title,description,priority,category}=req.body;
    db.run(`UPDATE tasks SET title=?,description=?,priority=?,category=?,updatedAt=datetime('now') WHERE id=? AND userId=?`,
      [title??task.title,description??task.description,priority??task.priority,category??task.category,id,req.userId],
      (e)=>{ if(e) return res.status(500).json({error:e.message});
        db.get('SELECT * FROM tasks WHERE id=?',[id],(e,t)=>res.json(fmt(t))); });
  });
});

app.delete('/api/v1/tasks/:id', auth, (req, res) => {
  const {id}=req.params;
  db.get('SELECT id FROM tasks WHERE id=? AND userId=?',[id,req.userId],(e,t)=>{
    if(!t) return res.status(404).json({error:'No encontrada'});
    db.run('DELETE FROM tasks WHERE id=? AND userId=?',[id,req.userId],(e)=>{
      if(e) return res.status(500).json({error:e.message}); res.status(204).send(); });
  });
});

app.patch('/api/v1/tasks/:id/complete', auth, (req, res) => {
  const {id}=req.params;
  db.get('SELECT * FROM tasks WHERE id=? AND userId=?',[id,req.userId],(e,task)=>{
    if(!task) return res.status(404).json({error:'No encontrada'});
    db.run(`UPDATE tasks SET completed=1,updatedAt=datetime('now') WHERE id=? AND userId=?`,[id,req.userId],
      (e)=>{ if(e) return res.status(500).json({error:e.message});
        db.get('SELECT * FROM tasks WHERE id=?',[id],(e,t)=>res.json(fmt(t))); });
  });
});

app.get('/api/v1/tasks/:id', auth, (req, res) => {
  db.get('SELECT * FROM tasks WHERE id=? AND userId=?',[req.params.id,req.userId],(e,t)=>{
    if(!t) return res.status(404).json({error:'No encontrada'}); res.json(fmt(t)); });
});

app.get('/', (req, res) => res.json({ status: 'TaskMaster API running', version: '1.0.0' }));
app.listen(PORT, () => console.log(`TaskMaster API en puerto ${PORT}`));
