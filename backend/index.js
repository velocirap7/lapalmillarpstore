require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const DISCORD_REGISTER_WEBHOOK = process.env.DISCORD_REGISTER_WEBHOOK;
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const User = require('./models/User');
const Product = require('./models/Product');
const Log = require('./models/Log');
const Announcement = require('./models/Announcement');
const Purchase = require('./models/Purchase');
const Category = require('./models/Category');

const app = express();
app.use(express.json());
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// --- DISCORD WEBHOOK HELPER ---
const sendDiscordWebhook = async (url, embed) => {
    if (!url) return;
    try {
        await axios.post(url, {
            embeds: [{
                ...embed,
                color: embed.color || 0xff2e2e,
                timestamp: new Date(),
                footer: { text: 'Sistema de Logs | La Palmilla RP' }
            }]
        });
    } catch (err) { console.error('Webhook error:', err.message); }
};

mongoose.connect(process.env.MONGO_URI)
    .then(async () => {
        console.log('MongoDB Connected');
        // Seed initial categories if none exist
        const count = await Category.countDocuments();
        if (count === 0) {
            const initial = [
                { name: 'VIP', icon: 'Star', order: 1 },
                { name: 'Vehículos', icon: 'Car', order: 2 },
                { name: 'Dinero', icon: 'Coins', order: 3 },
                { name: 'Legal', icon: 'Scale', order: 4 },
                { name: 'Ilegal', icon: 'ShieldAlert', order: 5 }
            ];
            await Category.insertMany(initial);
            console.log('Initial categories seeded');
        }
    })
    .catch(err => console.error(err));

// Middleware
const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

const adminMiddleware = async (req, res, next) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user || user.role !== 'admin') {
            return res.status(403).json({ error: 'Requires admin privileges' });
        }
        next();
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
};

// Utils
const createLog = async (username, action, details) => {
    const log = new Log({ userDiscordId: 'WEB', username, action, details });
    await log.save();
    // Webhook logic skipped for brevity in this replace call but should exist in actual file
};

// --- AUTH ROUTES ---
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password, birthdate, platform } = req.body;
        if (!username || !email || !password || !birthdate) return res.status(400).json({ error: 'Todos los campos son obligatorios' });
        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) return res.status(400).json({ error: 'El email o usuario ya está en uso' });
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newUser = new User({ username, email, password: hashedPassword, birthdate, platform: platform || 'PC', avatar: `https://ui-avatars.com/api/?name=${encodeURIComponent(username)}&background=random&color=fff` });
        await newUser.save();await sendDiscordWebhook(process.env.DISCORD_REGISTER_WEBHOOK, {
    title: '🆕 Nuevo Registro en la Web',
    description: 'Un usuario se ha registrado correctamente.',
    fields: [
        { name: '👤 Usuario', value: newUser.username, inline: true },
        { name: '📧 Email', value: newUser.email, inline: true },
        { name: '🆔 ID Usuario', value: newUser._id.toString(), inline: true },
        { name: '🕒 Fecha', value: new Date().toLocaleString(), inline: false }
    ],
    color: 0x00ff99
});
        const token = jwt.sign({ id: newUser._id, role: newUser.role, platform: newUser.platform }, process.env.JWT_SECRET || 'secret123', { expiresIn: '7d' });
        res.json({ token, message: 'Registro exitoso' });
    } catch (err) {
        console.error('Registration Error:', err);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ error: 'Credenciales inválidas' });
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ error: 'Credenciales inválidas' });
        const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET || 'secret123', { expiresIn: '7d' });

        await sendDiscordWebhook(process.env.DISCORD_LOGINS_WEBHOOK, {
            title: '🔑 Inicio de Sesión Detectado',
            description: `El usuario **${user.username}** ha accedido a su cuenta.`,
            fields: [
                { name: 'Email', value: user.email, inline: true },
                { name: 'Plataforma', value: user.platform || 'Desconocida', inline: true }
            ],
            color: 0x5865F2
        });

        res.json({ token, message: 'Inicio de sesión exitoso' });
    } catch (err) {
        console.error('Login Error:', err);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

// --- CATEGORY ROUTES ---
app.get('/api/categories', async (req, res) => {
    try {
        const categories = await Category.find().sort({ order: 1 });
        res.json(categories);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/categories', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const newCat = new Category(req.body);
        await newCat.save();
        res.json(newCat);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.put('/api/categories/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const cat = await Category.findByIdAndUpdate(req.params.id, req.body, { new: true });
        res.json(cat);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/categories/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        await Category.findByIdAndDelete(req.params.id);
        res.json({ message: 'Category deleted' });
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// --- PRODUCT ROUTES ---
app.get('/api/products', async (req, res) => {
    try {
        const products = await Product.find();
        res.json(products);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/products/:id', async (req, res) => {
    try {
        const product = await Product.findById(req.params.id);
        res.json(product);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/products', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const newProduct = new Product(req.body);
        await newProduct.save();
        res.json(newProduct);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.put('/api/products/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const product = await Product.findByIdAndUpdate(req.params.id, req.body, { new: true });
        res.json(product);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/products/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        await Product.findByIdAndDelete(req.params.id);
        res.json({ message: 'Product deleted' });
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/products/buy/:id', authMiddleware, async (req, res) => {
    try {
        const product = await Product.findById(req.params.id);
        if (!product) return res.status(404).json({ error: 'Product not found' });
        const user = await User.findById(req.user.id);
        if (user.coins < product.price) return res.status(400).json({ error: 'Insufficient coins' });
        user.coins -= product.price;
        await user.save();
        const ticketNumber = `PALMILLA-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
        const purchase = new Purchase({ userId: user._id, username: user.username, productId: product._id, productName: product.name, price: product.price, ticketNumber });
        await purchase.save();

        await sendDiscordWebhook(process.env.DISCORD_PURCHASES_WEBHOOK, {
            title: '🛍️ Nueva Venta Realizada',
            description: `Se ha procesado una nueva compra en la tienda.`,
            fields: [
                { name: '👤 Usuario', value: user.username, inline: true },
                { name: '📦 Producto', value: product.name, inline: true },
                { name: '💰 Precio', value: `${product.price} CC`, inline: true },
                { name: '🎫 Ticket', value: `\`${ticketNumber}\``, inline: true }
            ],
            color: 0x27ae60
        });

        res.json({ message: 'Purchase successful', user, ticketNumber });
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// --- USER & ADMIN ACTIONS ---
app.get('/api/user/me', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/users/profile/logs', authMiddleware, async (req, res) => {
    try {
        const purchases = await Purchase.find({ userId: req.user.id }).sort({ date: -1 });
        res.json(purchases);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.patch('/api/users/profile/link', authMiddleware, async (req, res) => {
    try {
        const { pcUsername, consoleUsername, discordUsername } = req.body;
        const user = await User.findById(req.user.id);
        if (pcUsername !== undefined) user.pcUsername = pcUsername;
        if (consoleUsername !== undefined) user.consoleUsername = consoleUsername;
        if (discordUsername !== undefined) user.discordUsername = discordUsername;
        await user.save();
        res.json(user);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/users', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const users = await User.find().select('-password');
        res.json(users);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// --- BATTLE PASS SYSTEM ---
const BP_REWARDS = [
    { level: 1, name: "Kit de Bienvenida PC", prize: "500 CC" },
    { level: 2, name: "Vehículo Básico", prize: "Habanero" },
    { level: 3, name: "Bonus de Dinero", prize: "1000 CC" },
    { level: 4, name: "Caja Sorpresa", prize: "Lootbox Bronce" },
    { level: 5, name: "Kit VIP Temporal", prize: "3 Días VIP" },
];

app.post('/api/battlepass/claim', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (user.platform !== 'PC') return res.status(403).json({ error: 'Solo para usuarios de PC' });

        const now = new Date();
        const lastClaimed = user.battlePass.lastClaimed;

        if (lastClaimed) {
            const diffHours = (now - lastClaimed) / (1000 * 60 * 60);
            if (diffHours < 24) {
                const wait = Math.ceil(24 - diffHours);
                return res.status(400).json({ error: `Debes esperar ${wait} horas para el siguiente nivel` });
            }
        }

        const currentLvl = user.battlePass.currentLevel;
        if (currentLvl > BP_REWARDS.length) return res.status(400).json({ error: 'Has completado todos los niveles' });

        const reward = BP_REWARDS.find(r => r.level === currentLvl);

        // Entregar premio si es CC
        if (reward.prize.includes('CC')) {
            const amount = parseInt(reward.prize);
            user.coins += amount;
        }

        user.battlePass.currentLevel += 1;
        user.battlePass.lastClaimed = now;
        await user.save();

        res.json({ message: '¡Recompensa reclamada!', user, reward });
    } catch (err) { res.status(500).json({ error: 'Error del servidor' }); }
});

// --- JOB & BUSINESS SYSTEM ---
app.post('/api/admin/assign-job', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { userId, jobName, jobRole } = req.body;
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

        user.job.name = jobName;
        user.job.role = jobRole;
        user.job.isOpen = false;
        await user.save();
        res.json({ message: 'Trabajo asignado correctamente', user });
    } catch (err) { res.status(500).json({ error: 'Error del servidor' }); }
});

app.post('/api/user/toggle-job', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user.job.name) return res.status(400).json({ error: 'No tienes un trabajo asignado' });

        user.job.isOpen = !user.job.isOpen;
        await user.save();
        res.json({ message: `Negocio ${user.job.isOpen ? 'Abrir' : 'Cerrar'} exitoso`, user });
    } catch (err) { res.status(500).json({ error: 'Error del servidor' }); }
});

app.post('/api/user/update-job-image', authMiddleware, async (req, res) => {
    try {
        const { image } = req.body;
        const user = await User.findById(req.user.id);
        if (!user.job.name) return res.status(400).json({ error: 'No tienes un trabajo asignado' });

        user.job.image = image;
        await user.save();
        res.json({ message: 'Imagen de negocio actualizada', user });
    } catch (err) { res.status(500).json({ error: 'Error del servidor' }); }
});

app.get('/api/jobs/open', async (req, res) => {
    try {
        const usersWithJobs = await User.find({ "job.isOpen": true }).select('username job');
        res.json(usersWithJobs);
    } catch (err) { res.status(500).json({ error: 'Error del servidor' }); }
});

app.post('/api/users/manage-coins', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { username, amount, action } = req.body;
        const user = await User.findOne({ username: { $regex: new RegExp(`^${username}$`, 'i') } });
        if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
        const change = parseInt(amount);
        if (action === 'add') user.coins += change;
        else user.coins = Math.max(0, user.coins - change);
        await user.save();
        res.json(user);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        if (req.params.id === req.user.id) return res.status(400).json({ error: 'No puedes eliminarte a ti mismo.' });
        await User.findByIdAndDelete(req.params.id);
        res.json({ message: 'Usuario eliminado' });
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/admin/purchases', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const purchases = await Purchase.find().sort({ date: -1 });
        res.json(purchases);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/purchases/recent', async (req, res) => {
    try {
        const purchases = await Purchase.find()
            .sort({ date: -1 })
            .limit(10)
            .select('username productName date');
        res.json(purchases);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// --- ANNOUNCEMENTS ---
app.get('/api/announcements', async (req, res) => {
    try {
        const announcements = await Announcement.find().sort({ date: -1 });
        res.json(announcements);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/announcements', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const newAnnouncement = new Announcement(req.body);
        await newAnnouncement.save();
        res.json(newAnnouncement);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/announcements/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        await Announcement.findByIdAndDelete(req.params.id);
        res.json({ message: 'Announcement deleted' });
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Backend server running on port ${PORT}`));
