// server.js
import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import fs from "fs/promises";
import path from "path";
import mongoose from "mongoose";
import dotenv from "dotenv";

dotenv.config();

const app = express();

// --- MongoDB Configuration ---
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27010/neutrolink";

mongoose.connect(MONGODB_URI)
    .then(() => console.log("Conectado a MongoDB Atlas"))
    .catch(err => console.error("Error conectando a MongoDB:", err));

// --- Schemas & Models ---

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    email: { type: String },
    display_name: { type: String },
    bio: { type: String },
    metadata: {
        registeredAt: { type: String },
        status: { type: String, default: "online" },
        anonymous_mode: { type: Boolean, default: false },
        tier: { type: String, default: "BASIC" },
        lastLogin: { type: String },
        lastIp: { type: String }
    },
    privacy: {
        see_profile: { type: String, default: "all" },
        send_dm: { type: String, default: "all" },
        see_status: { type: String, default: "all" },
        send_requests: { type: String, default: "all" }
    },
    personalization: {
        theme: { type: String, default: "dark" },
        accent: { type: String, default: "#10b981" }
    },
    sessions: [{
        id: String,
        ip: String,
        userAgent: String,
        location: String,
        createdAt: String,
        lastActive: String
    }]
});

const ServerSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    owner: { type: String, required: true },
    description: { type: String },
    icon: { type: String },
    roles: [{
        id: String,
        name: String,
        color: String,
        permissions: [String]
    }],
    channels: [{
        id: String,
        name: String,
        type: String
    }],
    members: [{
        username: String,
        roles: [String],
        nickname: String,
        isMuted: { type: Boolean, default: false }
    }],
    invites: [{
        code: String,
        generatedBy: String,
        maxUses: Number,
        uses: Number,
        expires: String
    }],
    bans: [String]
});

const MessageSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true },
    sender: { type: String, required: true },
    targetId: { type: String, required: true },
    targetType: { type: String, required: true },
    channelId: { type: String },
    text: { type: String, required: true },
    timestamp: { type: String },
    edited: { type: Boolean, default: false }
});

const FriendSchema = new mongoose.Schema({
    type: { type: String, default: 'friend' },
    user: { type: String, required: true },
    friend: { type: String },
    target: { type: String }, // For blocks
    date: { type: String }
});

const LogSchema = new mongoose.Schema({
    timestamp: { type: String },
    type: { type: String },
    username: String,
    ip: String,
    sessionId: String,
    serverId: String,
    serverName: String,
    updatedBy: String,
    channelName: String,
    creator: String,
    deletedBy: String,
    inviteCode: String,
    roleName: String
});

const User = mongoose.model("User", UserSchema);
const Server = mongoose.model("Server", ServerSchema);
const Message = mongoose.model("Message", MessageSchema);
const Friend = mongoose.model("Friend", FriendSchema);
const Log = mongoose.model("Log", LogSchema);

// In-memory signaling for calls (Production should use WebSockets/Redis)
const callSignals = new Map();

// --- Helpers ---
async function logEvent(type, details) {
    try {
        const logEntry = {
            timestamp: new Date().toISOString(),
            type,
            ...details
        };
        console.log("LOG:", JSON.stringify(logEntry, null, 2));
        const newLog = new Log(logEntry);
        await newLog.save();
        const count = await Log.countDocuments();
        if (count > 1000) {
            await Log.findOneAndDelete({}, { sort: { timestamp: 1 } });
        }
    } catch (err) {
        console.error("Error al guardar log:", err);
    }
}

app.use(express.json());
app.use(express.static("public"));

app.get("/ping", (req, res) => res.send("pong"));

// Registro
app.post("/register", async (req, res) => {
  const { username, password, email } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Nombre de usuario y contraseña son obligatorios" });

  try {
    const existing = await User.findOne({ username });
    if (existing) {
        return res.status(400).json({ error: "El nombre de usuario ya está en uso" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const userIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    
    const newUser = new User({ 
        username, 
        password: hashedPassword, 
        email: email || null,
        display_name: username,
        bio: "",
        metadata: { 
            registeredAt: new Date().toISOString(),
            status: "online",
            anonymous_mode: false,
            tier: "BASIC"
        },
        privacy: {
            see_profile: "all",
            send_dm: "all",
            see_status: "all",
            send_requests: "all"
        },
        personalization: {
            theme: "dark",
            accent: "#10b981"
        },
        sessions: []
    });
    await newUser.save();

    res.json({ message: "Usuario registrado con éxito. Ya puedes iniciar sesión." });
  } catch (err) {
    console.error("Error en registro:", err);
    res.status(500).json({ error: "Error interno al registrar el usuario" });
  }
});

// Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) return res.status(400).json({ error: "Credenciales incompletas" });

  try {
    const user = await User.findOne({ username });
    
    if (!user) return res.status(400).json({ error: "El usuario no existe" });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ error: "Contraseña incorrecta" });

    const userIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const session = {
        id: "sess-" + Date.now(),
        ip: userIP,
        userAgent: req.headers['user-agent'] || "Unknown Device",
        location: "LatAm South (IP-Sync)",
        createdAt: new Date().toISOString(),
        lastActive: new Date().toISOString()
    };

    user.sessions = user.sessions || [];
    user.sessions.unshift(session);
    if (user.sessions.length > 5) user.sessions.pop();
    
    user.metadata.lastLogin = session.createdAt;
    user.metadata.lastIp = userIP;

    await User.findOneAndUpdate({ username }, {
        sessions: user.sessions,
        metadata: user.metadata
    });
    await logEvent("LOGIN_SUCCESS", { username, ip: userIP, sessionId: session.id });

    const token = jwt.sign({ username, sessionId: session.id }, process.env.JWT_SECRET || "clave_secreta", { expiresIn: "10h" });
    res.json({ message: "Login exitoso", token });
  } catch (err) {
    console.error("Error en login:", err);
    res.status(500).json({ error: "Error interno al procesar el login" });
  }
});

// Middleware para verificar JWT
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ error: "Token no proporcionado" });

    try {
        const decoded = jwt.verify(token.replace("Bearer ", ""), "clave_secreta");
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: "Token inválido o expirado" });
    }
};

const PORT = process.env.PORT || 3000;

// Social & Security Endpoints
// --- Social & Security Implementation (MongoDB) ---

// --- Social & Security Endpoints ---
// Bot de Moderación Automática (NeutroGuard)
function neutroGuardScan(text) {
    const forbidden = ["spam", "hack", "virus", "kill", "die", "toxic"];
    const detected = forbidden.filter(word => text.toLowerCase().includes(word));
    return { isSafe: detected.length === 0, detectedWords: detected };
}

// PERMISSION CONSTANTS
const PERMS = {
    ADMINISTRATOR: "ADMINISTRATOR",
    MANAGE_SERVER: "MANAGE_SERVER",
    VIEW_LOGS: "VIEW_LOGS",
    MANAGE_ROLES: "MANAGE_ROLES",
    INVITE_USERS: "INVITE_USERS",
    CREATE_CHANNEL: "CREATE_CHANNEL",
    DELETE_CHANNEL: "DELETE_CHANNEL",
    VIEW_CHANNEL: "VIEW_CHANNEL",
    SEND_MESSAGES: "SEND_MESSAGES",
    DELETE_MESSAGES: "DELETE_MESSAGES",
    PIN_MESSAGES: "PIN_MESSAGES",
    KICK_MEMBERS: "KICK_MEMBERS",
    BAN_MEMBERS: "BAN_MEMBERS",
    MUTE_MEMBERS: "MUTE_MEMBERS",
    MANAGE_NICKNAMES: "MANAGE_NICKNAMES"
};

const checkPerm = (requiredPerm) => async (req, res, next) => {
    const { serverId } = req.params;
    const server = await Server.findOne({ id: serverId });
    if (!server) return res.status(404).json({ error: "Servidor no encontrado" });

    const member = server.members.find(m => m.username === req.user.username);
    if (!member) return res.status(403).json({ error: "No eres miembro de este servidor" });

    if (server.owner === req.user.username) return next();

    const memberRoles = member.roles || [];
    const hasPerm = memberRoles.some(roleId => {
        const role = (server.roles || []).find(r => r.id === roleId);
        if (!role) return false;
        if (role.permissions.includes(PERMS.ADMINISTRATOR)) return true;
        return role.permissions.includes(requiredPerm);
    });

    if (!hasPerm && requiredPerm) {
        return res.status(403).json({ error: `Acceso Denegado: Requiere permiso '${requiredPerm}'` });
    }
    req.server = server;
    next();
};

app.get("/api/profile", verifyToken, async (req, res) => {
    const user = await User.findOne({ username: req.user.username }).lean();
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });
    res.json({ 
        username: user.username,
        email: user.email,
        display_name: user.display_name || user.username,
        bio: user.bio || "",
        metadata: user.metadata,
        privacy: user.privacy || {},
        personalization: user.personalization || {},
        sessions: user.sessions || []
    });
});

app.put("/api/profile", verifyToken, async (req, res) => {
    try {
        const { display_name, bio, status, anonymous_mode, personalization, privacy } = req.body;
        const user = await User.findOne({ username: req.user.username });
        
        if (!user) return res.status(404).json({ error: "Usuario no encontrado en la base de datos" });

        const update = {};
        if (display_name !== undefined) update.display_name = display_name;
        if (bio !== undefined) update.bio = bio.replace(/<[^>]*>?/gm, '').substring(0, 120);
        
        if (status || anonymous_mode !== undefined) {
            update.metadata = { ...user.metadata };
            if (status) update.metadata.status = status;
            if (anonymous_mode !== undefined) update.metadata.anonymous_mode = anonymous_mode;
        }
        if (personalization) update.personalization = { ...(user.personalization || {}), ...personalization };
        if (privacy) update.privacy = { ...(user.privacy || {}), ...privacy };
        
        await User.findOneAndUpdate({ username: req.user.username }, update);
        res.json({ message: "Perfil actualizado con éxito" });
    } catch (err) {
        console.error("Error actualizando perfil:", err);
        res.status(500).json({ error: "Error al guardar el perfil" });
    }
});

app.put("/api/profile/password", verifyToken, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const user = await User.findOne({ username: req.user.username });
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

    const valid = await bcrypt.compare(oldPassword, user.password);
    if (!valid) return res.status(401).json({ error: "Contraseña actual incorrecta" });

    const newHash = await bcrypt.hash(newPassword, 10);
    await User.findOneAndUpdate({ username: req.user.username }, { password: newHash, sessions: [] });
    res.json({ message: "Contraseña actualizada. Por favor, inicia sesión de nuevo." });
});

app.delete("/api/profile/sessions/:sessionId", verifyToken, async (req, res) => {
    const { sessionId } = req.params;
    await User.findOneAndUpdate(
        { username: req.user.username },
        { $pull: { sessions: { id: sessionId } } }
    );
    res.json({ message: "Sesión cerrada correctamente" });
});

app.delete("/api/profile/account", verifyToken, async (req, res) => {
    const { password } = req.body;
    const user = await User.findOne({ username: req.user.username });
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: "Contraseña incorrecta" });

    await User.deleteOne({ username: req.user.username });
    res.json({ message: "Cuenta eliminada permanentemente" });
});

app.get("/api/profile/v/:username", verifyToken, async (req, res) => {
    const targetUser = await User.findOne({ username: req.params.username }).lean();
    if (!targetUser) return res.status(404).json({ error: "Usuario no encontrado" });

    const isOwner = req.user.username === targetUser.username;
    
    if (isOwner) {
        return res.json({
            username: targetUser.username,
            display_name: targetUser.display_name || targetUser.username,
            bio: targetUser.bio || "",
            metadata: targetUser.metadata,
            privacy: targetUser.privacy || {},
            personalization: targetUser.personalization || {}
        });
    }

    const isFriend = await Friend.exists({
        type: 'friend',
        $or: [
            { user: req.user.username, friend: targetUser.username },
            { user: targetUser.username, friend: req.user.username }
        ]
    });

    const privacy = targetUser.privacy || { see_profile: "all", see_status: "all" };

    if (targetUser.metadata?.anonymous_mode) {
        return res.json({
            username: targetUser.username,
            display_name: "Usuario Anónimo",
            bio: "Este usuario está en modo incógnito.",
            isAnonymous: true,
            metadata: { status: targetUser.metadata.status }
        });
    }

    const canSeeProfile = privacy.see_profile === "all" || (privacy.see_profile === "friends" && isFriend);
    const canSeeStatus = privacy.see_status === "all" || (privacy.see_status === "friends" && isFriend);

    if (!canSeeProfile) {
        return res.json({
            username: targetUser.username,
            display_name: targetUser.display_name || targetUser.username,
            bio: "Perfil privado",
            isPrivate: true,
            metadata: { status: canSeeStatus ? targetUser.metadata.status : "offline" }
        });
    }

    res.json({ 
        username: targetUser.username,
        display_name: targetUser.display_name || targetUser.username,
        bio: targetUser.bio || "",
        metadata: {
            ...targetUser.metadata,
            status: canSeeStatus ? targetUser.metadata.status : "offline"
        }
    });
});

// Búsqueda de usuarios
app.get("/api/users/search", verifyToken, async (req, res) => {
    const q = (req.query.q || "").toLowerCase();
    const matches = await User.find(
        { username: { $regex: q, $options: 'i' } },
        { username: 1, _id: 0 }
    ).where('username').ne(req.user.username);
    res.json(matches);
});

// Servidores donde el usuario es miembro
app.get("/api/servers", verifyToken, async (req, res) => {
    try {
        const userServers = await Server.find({ "members.username": req.user.username }).lean();
        res.json(userServers);
    } catch (err) {
        res.status(500).json({ error: "Error al cargar servidores" });
    }
});

app.post("/api/servers", verifyToken, async (req, res) => {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: "El nombre es obligatorio" });

    try {
        // Verificar límites por tier
        const user = await User.findOne({ username: req.user.username });
        const serverCount = await Server.countDocuments({ owner: req.user.username });
        
        const tier = user?.metadata?.tier || "BASIC";
        if (tier === "BASIC" && serverCount >= 5) {
            return res.status(403).json({ error: "Límite de servidores alcanzado para el plan Basic (Máx 5). Sube a Platinum para servidores ilimitados." });
        }

        const ownerRoleId = "role-owner-" + Date.now();
        const memberRoleId = "role-member-" + Date.now();

        const newServer = new Server({
            id: "srv-" + Date.now(),
            name,
            owner: req.user.username,
            roles: [
                { id: ownerRoleId, name: "Owner", color: "#f59e0b", permissions: Object.values(PERMS) },
                { id: memberRoleId, name: "Miembro", color: "#94a3b8", permissions: [PERMS.SEND_MESSAGES] }
            ],
            channels: [
                { id: "ch-gen-" + Date.now(), name: "general", type: "text" }
            ],
            members: [
                { username: req.user.username, roles: [ownerRoleId] }
            ]
        });

        await newServer.save();
        await logEvent("SERVER_CREATED", { serverId: newServer.id, serverName: name, creator: req.user.username });
        res.json(newServer);
    } catch (err) {
        console.error("CRITICAL: Error al crear servidor:", err);
        res.status(500).json({ error: "Error interno al crear el servidor: " + err.message });
    }
});

// Actualizar Ajustes del Servidor
app.put("/api/servers/:serverId", verifyToken, async (req, res) => {
    try {
        const { serverId } = req.params;
        const { name, description } = req.body;
        
        const server = await Server.findOneAndUpdate(
            { id: serverId, owner: req.user.username },
            { $set: { name, description } },
            { new: true }
        );

        if (!server) return res.status(404).json({ error: "Servidor no encontrado o no tienes permiso" });

        await logEvent("SERVER_UPDATED", { serverId, serverName: server.name, updatedBy: req.user.username });
        res.json(server);
    } catch (err) {
        res.status(500).json({ error: "Error interno al actualizar servidor" });
    }
});

// Generar invitación Pro
app.post("/api/servers/:serverId/invites", verifyToken, checkPerm(PERMS.INVITE_USERS), async (req, res) => {
    try {
        const { serverId } = req.params;
        const { maxUses, expiresInMinutes } = req.body;
        const code = Math.random().toString(36).substring(2, 8).toUpperCase();
        
        const newInvite = { 
            code, 
            generatedBy: req.user.username, 
            maxUses: maxUses || null,
            uses: 0,
            expires: expiresInMinutes ? new Date(Date.now() + expiresInMinutes * 60000).toISOString() : null 
        };
        
        await Server.findOneAndUpdate(
            { id: serverId },
            { $push: { invites: newInvite } }
        );
        res.json(newInvite);
    } catch (err) {
        res.status(500).json({ error: "Error interno" });
    }
});

// Unirse a servidor por invitación
app.post("/api/invites/join", verifyToken, async (req, res) => {
    try {
        const { code } = req.body;
        const server = await Server.findOne({ "invites.code": code });
        if (!server) return res.status(404).json({ error: "Invitación inválida" });

        const invite = server.invites.find(i => i.code === code);
        if (invite.expires && new Date() > new Date(invite.expires)) return res.status(410).json({ error: "Invitación expirada" });
        if (invite.maxUses && invite.uses >= invite.maxUses) return res.status(410).json({ error: "Límite de usos alcanzado" });

        if (server.members.find(m => m.username === req.user.username)) {
            return res.status(400).json({ error: "Ya eres miembro" });
        }

        const memberRole = server.roles.find(r => r.name === "Miembro") || server.roles[1];
        
        await Server.findOneAndUpdate(
            { id: server.id, "invites.code": code },
            { 
                $push: { members: { username: req.user.username, roles: [memberRole.id] } },
                $inc: { "invites.$.uses": 1 }
            }
        );

        await logEvent("MEMBER_JOINED", { serverId: server.id, username: req.user.username, inviteCode: code });
        res.json({ message: "Te has unido", serverId: server.id });
    } catch (err) {
        res.status(500).json({ error: "Error al unirse" });
    }
});

app.post("/api/servers/:serverId/channels", verifyToken, checkPerm(PERMS.CREATE_CHANNEL), async (req, res) => {
    try {
        const { serverId } = req.params;
        const { name, type } = req.body;
        const newChannel = { id: "ch-" + Date.now(), name: (name || "nuevo-canal").toLowerCase(), type: type || "text" };
        
        await Server.findOneAndUpdate(
            { id: serverId },
            { $push: { channels: newChannel } }
        );
        
        await logEvent("CHANNEL_CREATED", { serverId, channelName: name, creator: req.user.username });
        res.json(newChannel);
    } catch (err) {
        res.status(500).json({ error: "Error al crear canal" });
    }
});

app.delete("/api/servers/:serverId/channels/:channelId", verifyToken, checkPerm(PERMS.DELETE_CHANNEL), async (req, res) => {
    try {
        const { serverId, channelId } = req.params;
        const server = await Server.findOne({ id: serverId });
        if (!server) return res.status(404).json({ error: "Servidor no encontrado" });

        const channel = server.channels.find(c => c.id === channelId);
        if (!channel) return res.status(404).json({ error: "Canal no encontrado" });
        if (channel.name === 'general') return res.status(403).json({ error: "No puedes borrar el canal general" });

        await Server.findOneAndUpdate(
            { id: serverId },
            { $pull: { channels: { id: channelId } } }
        );
        
        await logEvent("CHANNEL_DELETED", { serverId, channelName: channel.name, deletedBy: req.user.username });
        res.json({ message: "Canal eliminado" });
    } catch (err) {
        res.status(500).json({ error: "Error al eliminar canal" });
    }
});

// Mensajes
app.get("/api/messages/:type/:id", verifyToken, async (req, res) => {
    try {
        const { type, id } = req.params;
        let query = {};
        if (type === 'channel') {
            query = { channelId: id };
        } else {
            query = {
                targetType: 'friend',
                $or: [
                    { sender: req.user.username, targetId: id },
                    { sender: id, targetId: req.user.username }
                ]
            };
        }
        const messages = await Message.find(query).sort({ timestamp: 1 }).lean();
        res.json(messages);
    } catch (err) {
        res.status(500).json({ error: "Error al cargar mensajes" });
    }
});

app.post("/api/messages", verifyToken, async (req, res) => {
    try {
        const { targetId, targetType, channelId, text } = req.body;
        
        if (targetType === 'server' || targetType === 'channel') {
            const server = await Server.findOne({ id: targetId });
            if (!server || !server.members.find(m => m.username === req.user.username)) {
                return res.status(403).json({ error: "Sin acceso" });
            }
        }

        const scan = neutroGuardScan(text);
        if (!scan.isSafe) return res.status(400).json({ error: "Bloqueado por NeutroGuard" });

        const newMessage = new Message({
            id: "msg-" + Date.now(),
            sender: req.user.username,
            targetId,
            targetType, 
            channelId: channelId || null, 
            text,
            timestamp: new Date().toISOString()
        });
        await newMessage.save();
        res.json(newMessage);
    } catch (err) {
        res.status(500).json({ error: "Error al enviar mensaje" });
    }
});

app.put("/api/messages/:msgId", verifyToken, async (req, res) => {
    try {
        const { msgId } = req.params;
        const { text } = req.body;
        const msg = await Message.findOneAndUpdate(
            { id: msgId, sender: req.user.username },
            { $set: { text, edited: true } },
            { new: true }
        );
        if (!msg) return res.status(403).json({ error: "No permitido o mensaje no encontrado" });
        res.json(msg);
    } catch (err) {
        res.status(500).json({ error: "Error al editar mensaje" });
    }
});

app.delete("/api/messages/:msgId", verifyToken, async (req, res) => {
    try {
        const { msgId } = req.params;
        const msg = await Message.findOneAndDelete({ id: msgId, sender: req.user.username });
        if (!msg) return res.status(403).json({ error: "No permitido" });
        res.json({ message: "Mensaje eliminado" });
    } catch (err) {
        res.status(500).json({ error: "Error al eliminar mensaje" });
    }
});

// --- GESTIÓN SOCIAL AVANZADA ---
app.get("/api/friends", verifyToken, async (req, res) => {
    try {
        const friendList = await Friend.find({
            type: 'friend',
            $or: [{ user: req.user.username }, { friend: req.user.username }]
        }).lean();
        
        const results = await Promise.all(friendList.map(async f => {
            const friendName = f.user === req.user.username ? f.friend : f.user;
            const friendUser = await User.findOne({ username: friendName }, { "metadata.status": 1, "metadata.tier": 1 }).lean();
            return {
                username: friendName,
                status: friendUser?.metadata?.status || "offline",
                tier: friendUser?.metadata?.tier || "BASIC"
            };
        }));
        res.json(results);
    } catch (err) {
        res.status(500).json({ error: "Error al obtener amigos" });
    }
});

app.delete("/api/friends/:username", verifyToken, async (req, res) => {
    try {
        const { username } = req.params;
        await Friend.deleteMany({
            type: 'friend',
            $or: [
                { user: req.user.username, friend: username },
                { user: username, friend: req.user.username }
            ]
        });
        res.json({ message: "Amigo eliminado" });
    } catch (err) {
        res.status(500).json({ error: "Error al eliminar amigo" });
    }
});

app.post("/api/friends/block", verifyToken, async (req, res) => {
    try {
        const { username } = req.body;
        // Eliminar amistad
        await Friend.deleteMany({
            type: 'friend',
            $or: [
                { user: req.user.username, friend: username },
                { user: username, friend: req.user.username }
            ]
        });
        
        await new Friend({ type: 'block', user: req.user.username, target: username, date: new Date().toISOString() }).save();
        res.json({ message: "Usuario bloqueado" });
    } catch (err) {
        res.status(500).json({ error: "Error al bloquear" });
    }
});

// --- GESTIÓN AVANZADA DE SERVIDORES ---

// Eliminar Servidor
app.delete("/api/servers/:serverId", verifyToken, async (req, res) => {
    try {
        const { serverId } = req.params;
        const server = await Server.findOneAndDelete({ id: serverId, owner: req.user.username });

        if (!server) return res.status(404).json({ error: "No encontrado o sin permiso" });

        await logEvent("SERVER_DELETED", { serverId, serverName: server.name, owner: req.user.username });
        res.json({ message: "Servidor eliminado" });
    } catch (err) {
        res.status(500).json({ error: "Error al eliminar servidor" });
    }
});

// Crear Rol
app.post("/api/servers/:serverId/roles", verifyToken, checkPerm(PERMS.MANAGE_ROLES), async (req, res) => {
    try {
        const { serverId } = req.params;
        const { name, color, permissions } = req.body;
        const newRole = { id: "role-" + Date.now(), name: name || "Nuevo Rol", color: color || "#ffffff", permissions: permissions || [] };

        await Server.findOneAndUpdate({ id: serverId }, { $push: { roles: newRole } });
        await logEvent("ROLE_CREATED", { serverId, roleName: name, creator: req.user.username });
        res.json(newRole);
    } catch (err) {
        res.status(500).json({ error: "Error al crear rol" });
    }
});

// Editar Rol
app.put("/api/servers/:serverId/roles/:roleId", verifyToken, checkPerm(PERMS.MANAGE_ROLES), async (req, res) => {
    try {
        const { serverId, roleId } = req.params;
        const { name, color, permissions } = req.body;
        
        const server = await Server.findOne({ id: serverId });
        if (!server) return res.status(404).json({ error: "No encontrado" });

        const role = server.roles.find(r => r.id === roleId);
        if (!role) return res.status(404).json({ error: "Rol no encontrado" });
        if (role.name === 'Owner') return res.status(403).json({ error: "El rol Owner no es editable" });

        await Server.findOneAndUpdate(
            { id: serverId, "roles.id": roleId },
            { $set: { "roles.$.name": name, "roles.$.color": color, "roles.$.permissions": permissions } }
        );
        
        await logEvent("ROLE_UPDATED", { serverId, roleName: name || role.name, updatedBy: req.user.username });
        res.json({ message: "Rol actualizado" });
    } catch (err) {
        res.status(500).json({ error: "Error al editar rol" });
    }
});

// Eliminar Rol
app.delete("/api/servers/:serverId/roles/:roleId", verifyToken, checkPerm(PERMS.MANAGE_ROLES), async (req, res) => {
    try {
        const { serverId, roleId } = req.params;
        const server = await Server.findOne({ id: serverId });
        if (!server) return res.status(404).json({ error: "No encontrado" });

        const role = server.roles.find(r => r.id === roleId);
        if (!role) return res.status(404).json({ error: "No encontrado" });
        if (role.name === 'Owner') return res.status(403).json({ error: "No se puede borrar el rol Owner" });

        await Server.findOneAndUpdate(
            { id: serverId },
            { 
                $pull: { roles: { id: roleId } },
                $set: { "members.$[].roles": { $filter: { input: "$members.roles", as: "r", cond: { $ne: ["$$r", roleId] } } } }
            }
        );
        
        await logEvent("ROLE_DELETED", { serverId, roleName: role.name, deletedBy: req.user.username });
        res.json({ message: "Rol eliminado" });
    } catch (err) {
        res.status(500).json({ error: "Error al eliminar rol" });
    }
});

// Asignar Roles
app.put("/api/servers/:serverId/members/:username/roles", verifyToken, checkPerm(PERMS.MANAGE_ROLES), async (req, res) => {
    try {
        const { serverId, username } = req.params;
        const { roleIds } = req.body;
        
        const server = await Server.findOne({ id: serverId });
        if (!server) return res.status(404).json({ error: "No encontrado" });
        if (username === server.owner) return res.status(403).json({ error: "No editable para el dueño" });

        await Server.findOneAndUpdate(
            { id: serverId, "members.username": username },
            { $set: { "members.$.roles": roleIds } }
        );

        await logEvent("MEMBER_ROLES_UPDATED", { serverId, targetUser: username, updatedBy: req.user.username });
        res.json({ message: "Roles actualizados" });
    } catch (err) {
        res.status(500).json({ error: "Error al actualizar roles" });
    }
});

// MODERACIÓN: Kick
app.post("/api/servers/:serverId/members/:username/kick", verifyToken, checkPerm(PERMS.KICK_MEMBERS), async (req, res) => {
    try {
        const { serverId, username } = req.params;
        const server = await Server.findOne({ id: serverId });
        if (!server) return res.status(404).json({ error: "No encontrado" });
        if (username === server.owner) return res.status(403).json({ error: "No permitido" });
        
        await Server.findOneAndUpdate({ id: serverId }, { $pull: { members: { username } } });
        await logEvent("MEMBER_KICKED", { serverId, targetUser: username, moderator: req.user.username });
        res.json({ message: "Expulsado" });
    } catch (err) {
        res.status(500).json({ error: "Error en kick" });
    }
});

// MODERACIÓN: Ban
app.post("/api/servers/:serverId/members/:username/ban", verifyToken, checkPerm(PERMS.BAN_MEMBERS), async (req, res) => {
    try {
        const { serverId, username } = req.params;
        const server = await Server.findOne({ id: serverId });
        if (!server) return res.status(404).json({ error: "No encontrado" });
        if (username === server.owner) return res.status(403).json({ error: "No permitido" });
        
        await Server.findOneAndUpdate(
            { id: serverId },
            { 
                $pull: { members: { username } },
                $addToSet: { bans: username }
            }
        );
        
        await logEvent("MEMBER_BANNED", { serverId, targetUser: username, moderator: req.user.username });
        res.json({ message: "Baneado" });
    } catch (err) {
        res.status(500).json({ error: "Error en ban" });
    }
});

// MODERACIÓN: Mute
app.post("/api/servers/:serverId/members/:username/mute", verifyToken, checkPerm(PERMS.MUTE_MEMBERS), async (req, res) => {
    try {
        const { serverId, username } = req.params;
        const server = await Server.findOne({ id: serverId });
        if (!server) return res.status(404).json({ error: "No encontrado" });
        
        const member = server.members.find(m => m.username === username);
        if (!member) return res.status(404).json({ error: "Miembro no encontrado" });
        if (username === server.owner) return res.status(403).json({ error: "No permitido" });
        
        const newMuteState = !member.isMuted;
        await Server.findOneAndUpdate(
            { id: serverId, "members.username": username },
            { $set: { "members.$.isMuted": newMuteState } }
        );

        await logEvent(newMuteState ? "MEMBER_MUTED" : "MEMBER_UNMUTED", { serverId, targetUser: username, moderator: req.user.username });
        res.json({ message: newMuteState ? "Silenciado" : "Reactivado" });
    } catch (err) {
        res.status(500).json({ error: "Error en mute" });
    }
});

// Nickname
app.put("/api/servers/:serverId/members/:username/nickname", verifyToken, checkPerm(PERMS.MANAGE_NICKNAMES), async (req, res) => {
    try {
        const { serverId, username } = req.params;
        const { nickname } = req.body;
        await Server.findOneAndUpdate(
            { id: serverId, "members.username": username },
            { $set: { "members.$.nickname": nickname || null } }
        );
        res.json({ message: "Apodo actualizado" });
    } catch (err) {
        res.status(500).json({ error: "Error en nickname" });
    }
});

// Obtener Miembros
app.get("/api/servers/:serverId/members", verifyToken, async (req, res) => {
    try {
        const server = await Server.findOne({ id: req.params.serverId }, { members: 1 }).lean();
        if (!server) return res.status(404).json({ error: "No encontrado" });
        res.json(server.members || []);
    } catch (err) {
        res.status(500).json({ error: "Error" });
    }
});

// --- SISTEMA DE SEÑALIZACIÓN PARA LLAMADAS (WebRTC) ---
app.post("/api/calls/signal", verifyToken, async (req, res) => {
    try {
        const { target, signal } = req.body; // target: username del destinatario
        if (!target || !signal) return res.status(400).json({ error: "Datos incompletos" });

        if (!callSignals.has(target)) callSignals.set(target, []);
        callSignals.get(target).push({ from: req.user.username, signal, type: signal.type, timestamp: Date.now() });
        
        // Limpiar señales antiguas
        if (callSignals.get(target).length > 20) callSignals.get(target).shift();
        
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: "Error de señalización" });
    }
});

app.get("/api/calls/signal", verifyToken, async (req, res) => {
    try {
        const mySignals = callSignals.get(req.user.username) || [];
        callSignals.set(req.user.username, []); // Consumir señales
        res.json(mySignals);
    } catch (err) {
        res.status(500).json({ error: "Error obteniendo señales" });
    }
});

// Pagos y Membresías Mejorado
app.post("/api/pay", verifyToken, async (req, res) => {
    try {
        const { tier, cardName } = req.body; // tier: 'PREMIUM' (Basic) o 'PLATINUM'
        
        const tierData = {
            'PREMIUM': { name: 'Premium (Basic)', uploadLimit: '100MB', price: 5 },
            'PLATINUM': { name: 'Platinum', uploadLimit: '500MB', price: 15 }
        };

        if (!tierData[tier]) return res.status(400).json({ error: "Paquete no válido" });

        const user = await User.findOneAndUpdate(
            { username: req.user.username },
            { 
                $set: { 
                    "metadata.tier": tier,
                    "metadata.lastPurchase": { 
                        date: new Date().toISOString(), 
                        cardHolder: cardName,
                        amount: tierData[tier].price,
                        package: tierData[tier].name
                    }
                } 
            },
            { new: true }
        );

        if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

        await logEvent("PAYMENT_SUCCESS", { 
            username: req.user.username, 
            tier, 
            amount: tierData[tier].price,
            cardHolder: cardName 
        });
        
        res.json({ message: `¡Gracias! Ahora eres ${tierData[tier].name}`, tier: tier });
    } catch (err) {
        console.error("Error en pago:", err);
        res.status(500).json({ error: "Error procesando el pago" });
    }
});

// Manejo de errores global para evitar que el servidor se caiga silenciosamente
process.on('uncaughtException', (err) => {
    console.error('❌ CRASH: Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('⚠️ CRASH: Unhandled Rejection at:', promise, 'reason:', reason);
});

app.listen(PORT, () => {
    console.log(`🚀 Servidor profesional corriendo en http://localhost:${PORT}`);
});

// Middleware de manejo de errores para devolver JSON siempre
app.use((err, req, res, next) => {
    console.error("❌ API ERROR:", err);
    res.status(500).json({ error: "Error interno del servidor", details: err.message });
});

// Mantener el proceso vivo explícitamente si es necesario
setInterval(() => {
    // Esto asegura que el loop de eventos no se vacíe
}, 1000 * 60 * 60);


