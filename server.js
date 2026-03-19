import express from 'express';
import { JSONFilePreset } from 'lowdb/node';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'taskmaster_secret_2024';

// Middlewares globales
app.use(cors());
app.use(express.json());

// Middleware de autenticación
function auth(req, res, next) {
  const h = req.headers['authorization'];
  if (!h) return res.status(401).json({ error: 'Token requerido' });
  const token = h.startsWith('Bearer ') ? h.slice(7) : h;
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Token inválido' });
  }
}

async function startServer() {
  try {
    // Inicialización de DB
    const defaultData = { users: [], tasks: [], nextUserId: 1, nextTaskId: 1 };
    const db = await JSONFilePreset('db.json', defaultData);
    console.log('✅ Base de datos cargada correctamente');

    // --- RUTAS DE AUTH ---
    app.post('/api/v1/auth/register', async (req, res) => {
      const { name, email, password } = req.body;
      if (!name || !email || !password) return res.status(400).json({ error: 'Campos requeridos' });
      
      if (db.data.users.find(u => u.email === email)) {
        return res.status(409).json({ error: 'Email ya registrado' });
      }

      const id = db.data.nextUserId++;
      const user = { 
        id, 
        name, 
        email, 
        password: bcrypt.hashSync(password, 10), 
        createdAt: new Date().toISOString() 
      };

      db.data.users.push(user);
      await db.write();

      const token = jwt.sign({ userId: id }, JWT_SECRET, { expiresIn: '7d' });
      res.status(201).json({ token, user: { id, name, email } });
    });

    app.post('/api/v1/auth/login', (req, res) => {
      const { email, password } = req.body;
      const user = db.data.users.find(u => u.email === email);
      if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.status(401).json({ error: 'Credenciales incorrectas' });
      }
      const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
      res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
    });

    // --- RUTAS DE TAREAS ---
    app.get('/api/v1/tasks', auth, (req, res) => {
      let tasks = db.data.tasks.filter(t => t.userId === req.userId);
      if (req.query.completed !== undefined) {
        tasks = tasks.filter(t => t.completed === (req.query.completed === 'true'));
      }
      if (req.query.category) {
        tasks = tasks.filter(t => t.category === req.query.category);
      }
      res.json(tasks.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)));
    });

    app.post('/api/v1/tasks', auth, async (req, res) => {
      const { title, description = '', priority = 'MEDIUM', category = 'General' } = req.body;
      if (!title) return res.status(400).json({ error: 'Título requerido' });

      const id = db.data.nextTaskId++;
      const task = { 
        id, 
        userId: req.userId, 
        title, 
        description, 
        priority, 
        category, 
        completed: false,
        createdAt: new Date().toISOString(), 
        updatedAt: new Date().toISOString() 
      };

      db.data.tasks.push(task);
      await db.write();
      res.status(201).json(task);
    });

    app.put('/api/v1/tasks/:id', auth, async (req, res) => {
      const task = db.data.tasks.find(t => t.id === +req.params.id && t.userId === req.userId);
      if (!task) return res.status(404).json({ error: 'No encontrada' });

      const { title, description, priority, category } = req.body;
      if (title !== undefined) task.title = title;
      if (description !== undefined) task.description = description;
      if (priority !== undefined) task.priority = priority;
      if (category !== undefined) task.category = category;
      
      task.updatedAt = new Date().toISOString();
      await db.write();
      res.json(task);
    });

    app.delete('/api/v1/tasks/:id', auth, async (req, res) => {
      const idx = db.data.tasks.findIndex(t => t.id === +req.params.id && t.userId === req.userId);
      if (idx === -1) return res.status(404).json({ error: 'No encontrada' });

      db.data.tasks.splice(idx, 1);
      await db.write();
      res.status(204).send();
    });

    app.patch('/api/v1/tasks/:id/complete', auth, async (req, res) => {
      const task = db.data.tasks.find(t => t.id === +req.params.id && t.userId === req.userId);
      if (!task) return res.status(404).json({ error: 'No encontrada' });

      task.completed = true;
      task.updatedAt = new Date().toISOString();
      await db.write();
      res.json(task);
    });

    // Ruta de salud y raíz
    app.get('/', (req, res) => res.json({ status: 'TaskMaster API online', version: '1.1.0' }));

    // Inicio del servidor
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Servidor escuchando en http://0.0.0.0:${PORT}`);
    });

  } catch (error) {
    console.error('❌ Error fatal al arrancar:', error);
    process.exit(1);
  }
}

// Ejecutar el arranque
startServer();