// dashboard.js v4.0 - Professional Ecosystem
const token = localStorage.getItem("token");
let currentUser = null;
let currentTarget = null;
let currentServer = null; 
let actionCallback = null;
let isGlobalAdminUser = false; // Flag para administración NeutroLink Corp

const PREMIUM_BANNERS = {
    "Cyber Neon": "linear-gradient(135deg, #0f0c29, #302b63, #24243e)",
    "Gold Abyss": "linear-gradient(45deg, #1a1a1b, #434343)",
    "Emerald Mist": "linear-gradient(135deg, #064e3b, #059669)",
    "Sunset Vapor": "linear-gradient(135deg, #ff0844, #ffb199)",
    "Neutral Dark": "linear-gradient(135deg, #1e1f22, #2b2d31)"
};

// Helper para fetch robusto
async function safeFetch(url, options = {}) {
    const res = await fetch(url, options);
    const contentType = res.headers.get("content-type");
    
    if (res.ok) {
        if (contentType && contentType.includes("application/json")) return res.json();
        return res;
    }
    
    let errorMsg = "Error en la operación";
    if (contentType && contentType.includes("application/json")) {
        const err = await res.json();
        errorMsg = err.error || errorMsg;
    } else {
        errorMsg = `Error del servidor (${res.status})`;
    }
    throw new Error(errorMsg);
}

const elements = {
    messageList: document.getElementById("MessageList"),
    chatInput: document.getElementById("ChatMessageInput"),
    sendBtn: document.getElementById("SendMessageBtn"),
    chatHeader: document.getElementById("ChatTargetName"),
    friendsList: document.getElementById("FriendsList"),
    channelList: document.getElementById("ChannelList"),
    serverList: document.getElementById("ServerList"),
    channelHeader: document.getElementById("ChannelHeaderGroup"),
    searchInput: document.getElementById("UserSearch"),
    searchResults: document.getElementById("SearchResults"),
    toastContainer: document.getElementById("ToastContainer"),
    profileModal: document.getElementById("ProfileModal"),
    editProfileModal: document.getElementById("EditProfileModal"),
    serverSettingsModal: document.getElementById("ServerSettingsModal")
};

// --- INITIALIZATION ---
document.addEventListener("DOMContentLoaded", async () => {
    if (!token) return logout();
    await fetchProfile();
    await loadSocialData();
    setupEventListeners();
    applyPersonalization();
});

function logout() {
    localStorage.clear();
    window.location.href = "/index.html";
}

async function fetchProfile() {
    try {
        const res = await fetch("/api/profile", { headers: { "Authorization": `Bearer ${token}` } });
        if (!res.ok) throw new Error();
        currentUser = await res.json();
        document.getElementById("usernameDisplay").innerText = currentUser.display_name || currentUser.username;
        
        // Renderizar punto de estado pro
        const statusColors = { online: "#10b981", idle: "#f59e0b", dnd: "#ef4444", invisible: "#94a3b8" };
        const statusDot = document.getElementById("selfStatusDot");
        if (statusDot) {
            statusDot.style.background = statusColors[currentUser.metadata?.status] || "#10b981";
            statusDot.title = `Estado: ${currentUser.metadata?.status || 'online'}`;
        }
        
        const selector = document.getElementById("StatusSelector");
        if (selector) selector.value = currentUser.metadata?.status || "online";

        // Tier Badge Logic Mejorada
        const badge = document.getElementById("userTierBadge");
        if (badge) {
            const tier = currentUser.metadata?.tier || "BASIC";
            if (tier === "PREMIUM") {
                badge.innerText = "PREMIUM";
                badge.style.display = "inline-block";
                badge.style.background = "var(--primary)";
                badge.style.color = "#000";
            } else if (tier === "PLATINUM") {
                badge.innerText = "PLATINUM";
                badge.style.display = "inline-block";
                badge.style.background = "linear-gradient(135deg, #6366f1, #a855f7)";
                badge.style.color = "#fff";
                badge.style.fontWeight = "800";
                badge.style.boxShadow = "0 0 10px rgba(168, 85, 247, 0.5)";
            } else {
                badge.style.display = "none";
            }
        }

        // Mostrar Botón de Admin Global si es el usuario dueño o staff
        try {
            const adminCheck = await fetch("/api/admin/check", { headers: { "Authorization": `Bearer ${token}` } });
            if (adminCheck.ok) {
                const data = await adminCheck.json();
                isGlobalAdminUser = data.isGlobalAdmin;
                if (isGlobalAdminUser) {
                    const adminBtn = document.getElementById("GlobalAdminNavBtn");
                    if (adminBtn) adminBtn.style.display = "flex";
                }
            }
        } catch (adminErr) {
            console.warn("Global admin check failed, skipping shield icon.", adminErr);
        }
    } catch (e) { console.error("Profile fetch failed", e); }
}

function applyPersonalization() {
    if (!currentUser?.personalization) return;
    const { theme, accent } = currentUser.personalization;
    document.documentElement.style.setProperty('--primary', accent || "#10b981");
    // Implementación de tema (claro/oscuro) simplificada
    document.body.classList.toggle("light-mode", theme === "light");
}

async function loadSocialData() {
    await loadFriends();
    await loadServers();
}

// --- PROFESSIONAL ACTION MODAL (V7.0) ---
function openActionModal(title, desc, confirmLabel, onConfirm, hasInput = false, inputLabel = "") {
    document.getElementById("ActionTitle").innerText = title;
    document.getElementById("ActionDesc").innerHTML = desc;
    document.getElementById("ActionConfirmBtn").innerText = confirmLabel;
    
    const inputArea = document.getElementById("ActionInputArea");
    const inputField = document.getElementById("ActionInput");
    
    if (hasInput) {
        inputArea.style.display = "block";
        document.getElementById("ActionInputLabel").innerText = inputLabel;
        inputField.value = "";
    } else {
        inputArea.style.display = "none";
    }
    
    actionCallback = onConfirm;
    document.getElementById("ActionModal").style.display = "flex";
    
    const btn = document.getElementById("ActionConfirmBtn");
    btn.disabled = false;
    btn.style.opacity = "1";

    btn.onclick = async () => {
        const val = hasInput ? inputField.value.trim() : true;
        if (hasInput && !val) return;
        
        btn.disabled = true;
        btn.style.opacity = "0.5";
        
        try {
            await actionCallback(val);
        } catch (e) {
            console.error(e);
            showToast(e.message || "Error en la operación", "error");
        } finally {
            btn.disabled = false;
            btn.style.opacity = "1";
            closeActionModal();
        }
    };
}

function closeActionModal() {
    document.getElementById("ActionModal").style.display = "none";
}

// --- NOTIFICATIONS ---
function showToast(message, type = "success") {
    const toast = document.createElement("div");
    toast.className = `Toast ${type}`;
    const icons = { success: "✅", error: "🚫", social: "👥", info: "ℹ️" };
    toast.innerHTML = `<span>${icons[type] || "🔔"}</span> <span>${message}</span>`;
    elements.toastContainer.appendChild(toast);
    setTimeout(() => {
        toast.style.animation = "toastSlideIn 0.3s reverse forwards";
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// --- SERVERS & CHANNELS ---
async function loadServers() {
    try {
        const res = await fetch("/api/servers", { headers: { "Authorization": `Bearer ${token}` } });
        const servers = await res.json();
        elements.serverList.innerHTML = servers.map(s => `
            <div class="ServerIcon ${currentServer?.id === s.id ? 'active' : ''}" 
                 onclick="selectServer('${s.id}')" 
                 title="${s.name}">${s.name[0].toUpperCase()}</div>
        `).join("");
    } catch (e) { showToast("Error cargando servidores", "error"); }
}

async function selectServer(serverId) {
    try {
        const res = await fetch("/api/servers", { headers: { "Authorization": `Bearer ${token}` } });
        const servers = await res.json();
        currentServer = servers.find(s => s.id === serverId);
        if (!currentServer) return; // Salida segura
        
        document.getElementById("ActiveServerName").innerText = currentServer.name;
        elements.channelHeader.style.display = "flex";
        document.getElementById("ServerSettingsBtn").style.display = currentServer.owner === currentUser.username ? "block" : "none";

        renderChannels();
        loadServers();
        
        // CORRECCIÓN: Sincronizar UI de configuración si el modal está abierto
        if (elements.serverSettingsModal.style.display === "flex") {
            const activeTab = document.querySelector("#ServerSettingsModal .SettingsNav.active")?.dataset.tab || 'srv-general';
            switchSettingsTab(activeTab);
        }

        document.getElementById("MemberListSide").style.display = "flex";
        renderServerMembers();

        if (currentServer.channels?.length > 0) {
            selectTarget(currentServer.channels[0].id, 'channel', currentServer.channels[0].name);
        }
    } catch (e) { console.error(e); }
}

function renderChannels() {
    if (!currentServer) return;
    elements.channelList.innerHTML = currentServer.channels.map(c => `
        <div class="ChannelItem ${currentTarget?.id === c.id ? 'active' : ''}" onclick="selectTarget('${c.id}', 'channel', '${c.name}')">
            <span># ${c.name}</span>
        </div>
    `).join("");
}

// --- PROFILE EDIT (V4.0) ---
function openEditProfile() {
    closeProfile();
    elements.editProfileModal.style.display = "flex";
    switchEditTab('profile-basic');
}

function closeEditProfile() { elements.editProfileModal.style.display = "none"; }

function switchEditTab(tab) {
    const content = document.getElementById("EditProfileContent");
    document.querySelectorAll("#EditProfileModal .SettingsNav").forEach(n => n.classList.toggle("active", n.dataset.tab === tab));

    if (tab === 'profile-basic') {
        content.innerHTML = `
            <h2>Información Básica</h2>
            <div class="InputGroup" style="margin-top: 20px;">
                <label>Nombre a mostrar</label>
                <input type="text" id="EditDisplayName" value="${currentUser.display_name || ''}" style="width:100%">
            </div>
            <div class="InputGroup" style="margin-top: 15px;">
                <label>Biografía (Máx 120 car.)</label>
                <textarea id="EditBio" style="width:100%; min-height:80px;">${currentUser.bio || ''}</textarea>
            </div>
            <div style="margin-top: 15px; display: flex; align-items: center; gap: 10px;">
                <input type="checkbox" id="AnonModeToggle" ${currentUser.metadata?.anonymous_mode ? 'checked' : ''}>
                <label for="AnonModeToggle">Modo Anónimo (Oculta bio y nombre)</label>
            </div>
            <button onclick="saveProfile()" class="PrimaryBtn" style="margin-top:20px;">Guardar Cambios</button>
        `;
    } else if (tab === 'profile-privacy') {
        const p = currentUser.privacy || {};
        content.innerHTML = `
            <h2>Privacidad</h2>
            <div class="InputGroup">
                <label>¿Quién puede ver mi perfil?</label>
                <select id="PrivSeeProfile">
                    <option value="all" ${p.see_profile === 'all' ? 'selected' : ''}>Todos</option>
                    <option value="friends" ${p.see_profile === 'friends' ? 'selected' : ''}>Solo Amigos</option>
                </select>
            </div>
            <div class="InputGroup">
                <label>¿Quién puede ver mi estado?</label>
                <select id="PrivSeeStatus">
                    <option value="all" ${p.see_status === 'all' ? 'selected' : ''}>Todos</option>
                    <option value="friends" ${p.see_status === 'friends' ? 'selected' : ''}>Solo Amigos</option>
                </select>
            </div>
            <button onclick="savePrivacy()" class="PrimaryBtn">Actualizar Privacidad</button>
        `;
    } else if (tab === 'profile-security') {
        content.innerHTML = `
            <h2>Seguridad de Cuenta</h2>
            
            <section style="margin-bottom:30px; background:rgba(0,0,0,0.1); padding:15px; border-radius:10px;">
                <h3>Cambiar Contraseña</h3>
                <div class="InputGroup" style="margin-top:10px;">
                    <label>Contraseña Actual</label>
                    <input type="password" id="OldPass" placeholder="••••••••" style="width:100%">
                </div>
                <div class="InputGroup" style="margin-top:10px;">
                    <label>Nueva Contraseña</label>
                    <input type="password" id="NewPass" placeholder="••••••••" style="width:100%">
                </div>
                <button onclick="updatePassword()" class="PrimaryBtn" style="margin-top:15px; width:100%;">Actualizar Credenciales</button>
            </section>

            <section style="margin-bottom:30px;">
                <h3>Sesiones Activas (Pro Geolocation)</h3>
                <div id="SessionList" style="display:grid; gap:10px; margin-top:10px;">
                    ${currentUser.sessions?.map(s => `
                        <div class="LogItem" style="display:flex; justify-content:space-between; align-items:center; background:rgba(255,255,255,0.03);">
                            <div>
                                <div style="font-size:0.8rem; font-weight:800;">${s.userAgent.split(' ')[0]} <span style="font-weight:400; color:var(--primary); font-size:0.7rem;">[${s.location || 'Unknown'}]</span></div>
                                <div style="font-size:0.65rem; color:var(--text-muted)">${s.ip} • ${new Date(s.createdAt).toLocaleString()}</div>
                            </div>
                            ${s.id === localStorage.getItem("sessionId") ? '<span style="font-size:0.6rem; color:var(--primary);">Actual</span>' : `<button onclick="terminateSession('${s.id}')" style="background:transparent; border:none; color:#ef4444; cursor:pointer; font-size:0.75rem;">Cerrar</button>`}
                        </div>
                    `).join('') || 'Sin sesiones'}
                </div>
            </section>

            <div style="border-top: 1px solid rgba(255,0,0,0.2); padding-top:20px;">
                <h3 style="color:#ef4444">Zona Crítica</h3>
                <p style="font-size:0.75rem; color:var(--text-muted); margin-bottom:10px;">Esta acción eliminará todos tus datos, mensajes y servidores de forma permanente.</p>
                <button onclick="deleteAccount()" style="background:#ef4444; color:#fff; border:none; padding:12px; border-radius:8px; cursor:pointer; width:100%; font-weight:700;">ELIMINAR MI CUENTA</button>
        `;
    } else if (tab === 'profile-appearance') {
        content.innerHTML = `
            <h2>Personalización</h2>
            <div class="InputGroup">
                <label>Banner de Perfil (Premium)</label>
                <div style="display:grid; grid-template-columns: repeat(3, 1fr); gap:10px; margin-top:10px;">
                    ${Object.entries(PREMIUM_BANNERS).map(([name, value]) => `
                        <div onclick="selectBanner('${value}')" style="height:40px; background:${value}; border-radius:4px; cursor:pointer; border:${currentUser.personalization?.banner === value ? '2px solid var(--primary)' : '1px solid rgba(255,255,255,0.1)'}" title="${name}"></div>
                    `).join('')}
                    <div onclick="openActionModal('Banner Personalizado', 'Introduce la URL de tu imagen', 'Aplicar', (url) => selectBanner(url), true, 'URL de la imagen')" style="height:40px; background:rgba(255,255,255,0.05); border:1px dashed rgba(255,255,255,0.2); border-radius:4px; cursor:pointer; display:flex; align-items:center; justify-content:center; font-size:1rem;" title="Propio">+</div>
                </div>
            </div>
            <div class="InputGroup" style="margin-top:20px;">
                <label>Tema</label>
                <select id="AppearanceTheme">
                    <option value="dark" ${currentUser.personalization?.theme === 'dark' ? 'selected' : ''}>Oscuro</option>
                    <option value="light" ${currentUser.personalization?.theme === 'light' ? 'selected' : ''}>Claro</option>
                </select>
            </div>
            <div class="InputGroup">
                <label>Color de Acento</label>
                <input type="color" id="AppearanceAccent" value="${currentUser.personalization?.accent || '#10b981'}" style="width:100%; height:40px; border:none; background:transparent;">
            </div>
            <div class="InputGroup" style="margin-top:20px;">
                <label>URL de Foto de Perfil (Avatar)</label>
                <input type="text" id="AppearanceAvatar" value="${currentUser.personalization?.avatar || ''}" placeholder="URL de la imagen (ej: https://...)" class="AuthInput" style="padding:10px;">
            </div>
            <button onclick="saveAppearance()" class="PrimaryBtn">Aplicar Estilo</button>
        `;
    }
}

async function selectBanner(banner) {
    if (!currentUser.personalization) currentUser.personalization = {};
    currentUser.personalization.banner = banner;
    await saveAppearance();
    switchEditTab('profile-appearance');
}

async function saveProfile() {
    const body = {
        display_name: document.getElementById("EditDisplayName").value,
        bio: document.getElementById("EditBio").value,
        anonymous_mode: document.getElementById("AnonModeToggle").checked
    };
    await updateProfile(body);
}

async function savePrivacy() {
    const body = {
        privacy: {
            see_profile: document.getElementById("PrivSeeProfile").value,
            see_status: document.getElementById("PrivSeeStatus").value
        }
    };
    await updateProfile(body);
}

async function saveAppearance() {
    const avatar = document.getElementById("AppearanceAvatar")?.value;
    const body = {
        personalization: {
            theme: document.getElementById("AppearanceTheme")?.value || currentUser.personalization?.theme,
            accent: document.getElementById("AppearanceAccent")?.value || currentUser.personalization?.accent,
            banner: currentUser.personalization?.banner,
            avatar: avatar !== undefined ? avatar : currentUser.personalization?.avatar
        }
    };
    await updateProfile(body);
    await fetchProfile(); // Recargar para ver los cambios inmediatamente
    applyPersonalization();
}

async function updateProfile(body) {
    try {
        await safeFetch("/api/profile", {
            method: "PUT",
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
            body: JSON.stringify(body)
        });
        showToast("Cambios guardados", "success");
        await fetchProfile();
    } catch (e) {
        showToast(e.message, "error");
    }
}

async function changeStatus(status) {
    await updateProfile({ status });
    await fetchProfile();
    showToast(`Estado cambiado a ${status}`, "info");
}

async function updatePassword() {
    const oldPassword = document.getElementById("OldPass").value;
    const newPassword = document.getElementById("NewPass").value;
    if (!oldPassword || !newPassword) return showToast("Faltan datos", "error");

    try {
        await safeFetch("/api/profile/password", {
            method: "PUT",
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
            body: JSON.stringify({ oldPassword, newPassword })
        });
        showToast("Contraseña actualizada. Cierra sesión.", "success");
        setTimeout(logout, 2000);
    } catch (e) { showToast(e.message, "error"); }
}

async function deleteAccount() {
    openActionModal(
        "ELIMINAR CUENTA",
        "Esta acción es irreversible. Todos tus datos se borrarán para siempre. Confirma con tu contraseña.",
        "ELIMINAR PERMANENTEMENTE",
        async (password) => {
            await safeFetch("/api/profile/account", {
                method: "DELETE",
                headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
                body: JSON.stringify({ password })
            });
            showToast("Cuenta eliminada", "error");
            logout();
        },
        true,
        "Tu Contraseña"
    );
}

async function terminateSession(id) {
    if (!confirm("¿Cerrar esta sesión?")) return;
    const res = await fetch(`/api/profile/sessions/${id}`, {
        method: "DELETE",
        headers: { "Authorization": `Bearer ${token}` }
    });
    if (res.ok) {
        showToast("Sesión terminada", "info");
        await fetchProfile();
        switchEditTab('profile-security');
    }
}

// --- PROFILE MODAL ---
async function viewUserProfile(username) {
    try {
        const res = await fetch(`/api/profile/v/${username}`, { headers: { "Authorization": `Bearer ${token}` } });
        const user = await res.json();

        const card = document.querySelector("#ProfileModal .ProfileCard");
        const banner = document.querySelector("#ProfileModal .ProfileBanner");
        const avatar = document.querySelector("#ProfileModal .ProfileAvatarLarge");

        const accent = user.personalization?.accent || "#10b981";
        card.style.setProperty("--accent", accent);
        
        // Aplicar Banner
        const bannerVal = user.personalization?.banner || "linear-gradient(135deg, #1e1f22, #2b2d31)";
        if (bannerVal.startsWith("linear-gradient")) {
            banner.style.background = bannerVal;
            banner.style.backgroundImage = bannerVal;
        } else {
            banner.style.backgroundImage = `url('${bannerVal}')`;
            banner.style.backgroundSize = "cover";
            banner.style.backgroundPosition = "center";
        }

        document.getElementById("ProfileDisplayName").innerText = user.display_name || user.username;
        document.getElementById("ProfileUsername").innerText = `@${user.username}`;
        document.getElementById("ProfileBio").innerText = user.bio || "Este usuario prefiere mantener su bio en privado.";
        document.getElementById("ProfileEditBtn").style.display = (username === currentUser.username) ? "block" : "none";
        document.getElementById("ProfileCallBtn").style.display = (username !== currentUser.username) ? "block" : "none";
        
        // Mostrar controles de moderación si somos dueños o tenemos permisos y NO es nuestro perfil
        const modGroup = document.getElementById("ProfileModGroup");
        const globalModGroup = document.getElementById("ProfileGlobalModGroup");

        if (modGroup) {
            let hasServerModPerm = false;
            if (currentServer && username !== currentUser.username) {
                const me = currentServer.members?.find(m => m.username === currentUser.username);
                const isSrvOwner = currentServer.owner === currentUser.username;
                
                if (isSrvOwner) {
                    hasServerModPerm = true;
                } else if (me && me.roles) {
                    hasServerModPerm = me.roles.some(roleId => {
                        const role = currentServer.roles?.find(r => r.id === roleId);
                        return role && (role.permissions.includes('ADMINISTRATOR') || role.permissions.includes('BAN_MEMBERS') || role.permissions.includes('KICK_MEMBERS'));
                    });
                }
            }
            modGroup.style.display = hasServerModPerm ? "flex" : "none";
        }

        if (globalModGroup) {
            globalModGroup.style.display = (isGlobalAdminUser && username !== currentUser.username) ? "flex" : "none";
        }
        
        // Status Dot in Modal
        const statusColors = { online: "#10b981", idle: "#f59e0b", dnd: "#ef4444", invisible: "#94a3b8", offline: "#4b5563" };
        const avatarUrl = user.personalization?.avatar || "";
        
        if (avatarUrl) {
            avatar.style.backgroundImage = `url('${avatarUrl}')`;
            avatar.style.backgroundSize = "cover";
            avatar.style.backgroundPosition = "center";
            avatar.innerText = "";
        } else {
            avatar.style.backgroundImage = "none";
            avatar.innerText = (user.display_name || user.username).charAt(0).toUpperCase();
        }

        avatar.innerHTML += `<div style="position:absolute; bottom:5px; right:5px; width:20px; height:20px; border-radius:50%; background:${statusColors[user.metadata?.status || 'offline']}; border:4px solid #1e1f22;"></div>`;

        elements.profileModal.style.display = "flex";
    } catch (e) {
        console.error(e);
        showToast("Error al cargar perfil", "error");
    }
}

function closeProfile() { elements.profileModal.style.display = "none"; }

// --- SETTINGS MODAL ---
function openServerSettings() {
    elements.serverSettingsModal.style.display = "flex";
    switchSettingsTab('srv-general');
}
function closeSettings() { elements.serverSettingsModal.style.display = "none"; }

function switchSettingsTab(tab) {
    document.querySelectorAll("#ServerSettingsModal .SettingsNav").forEach(n => n.classList.toggle("active", n.dataset.tab === tab));
    const content = document.getElementById("SettingsContent");
    
    if (tab === 'srv-general') {
        content.innerHTML = `
            <h2 style="margin-bottom:20px;">Visión General</h2>
            <div class="InputGroup">
                <label>Nombre del Servidor</label>
                <input type="text" value="${currentServer.name}" id="SetSrvName" placeholder="Escribe el nombre del servidor...">
            </div>
            <div class="InputGroup">
                <label>Descripción (Opcional)</label>
                <textarea id="SetSrvDesc" style="width:100%; height:80px; background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.1); border-radius:8px; color:#fff; padding:10px;">${currentServer.description || ""}</textarea>
            </div>
            <button onclick="saveServerGeneral()" class="PrimaryBtn" style="margin-top:20px;">Guardar Cambios</button>
            <div style="margin-top: 60px; border-top: 1px solid rgba(239, 68, 68, 0.2); padding-top: 30px;">
                <h3 style="color:#ef4444; margin-bottom:10px;">Zona de Peligro</h3>
                <p style="font-size:0.8rem; color:var(--text-muted); margin-bottom:15px;">Una vez que eliminas un servidor, no hay vuelta atrás. Por favor, asegúrate de que quieres hacer esto.</p>
                <button onclick="deleteCurrentServer()" class="DangerBtn" style="padding:12px 24px;">ELIMINAR SERVIDOR</button>
            </div>
        `;
    } else if (tab === 'srv-roles') {
        renderRolesTab();
    } else if (tab === 'srv-security') {
        content.innerHTML = `
            <h2>Seguridad de Invitaciones</h2>
            <div style="background:rgba(255,255,255,0.05); padding:20px; border-radius:12px; margin-bottom:20px;">
                <h3>Generar Invitación Pro</h3>
                <div style="display:grid; grid-template-columns: 1fr 1fr; gap:15px; margin-top:15px;">
                    <div class="InputGroup">
                        <label>Usos Máximos</label>
                        <select id="InvMaxUses">
                            <option value="0">Ilimitado</option>
                            <option value="1">1 Uso (Single-use)</option>
                            <option value="5">5 Usos</option>
                            <option value="10">10 Usos</option>
                        </select>
                    </div>
                    <div class="InputGroup">
                        <label>Expiración</label>
                        <select id="InvExpires">
                            <option value="0">Nunca</option>
                            <option value="30">30 Minutos</option>
                            <option value="1440">24 Horas</option>
                        </select>
                    </div>
                </div>
                <button id="GenerateInviteBtn" onclick="generateAdvancedInvite()" class="PrimaryBtn" style="width:100%; margin-top:15px;">Generar Enlace Seguro</button>
            </div>
            <h3>Enlaces Activos</h3>
            <div id="InviteList">
                ${currentServer.invites?.map(i => {
                    const fullUrl = `${window.location.origin}/join?code=${i.code}`;
                    return `
                    <div class="LogItem" style="font-size:0.85rem; display:flex; flex-direction:column; gap:8px;">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <span class="InviteCode" style="background:var(--primary); color:#000; padding:2px 6px; border-radius:4px; font-weight:800;">${i.code}</span>
                            <span style="color:var(--text-muted); font-size:0.75rem;">Por ${i.generatedBy}</span>
                        </div>
                        <div style="background:rgba(0,0,0,0.2); padding:8px; border-radius:6px; font-family:'JetBrains Mono', monospace; font-size:0.7rem; color:var(--primary); word-break:break-all;">
                            ${fullUrl}
                        </div>
                    </div>
                `}).join("") || "No hay invitaciones activas."}
            </div>
        `;
    } else if (tab === 'srv-channels') {
        content.innerHTML = `
            <h2>Gestión de Canales</h2>
            <div id="ChannelManagerList" style="margin-top:20px;">
                ${currentServer.channels?.map(c => `
                    <div class="LogItem" style="display:flex; justify-content:space-between; align-items:center;">
                        <span># ${c.name}</span>
                        ${c.name !== 'general' ? `<button onclick="deleteChannel('${c.id}', '${c.name}')" style="background:transparent; border:none; color:#ef4444; cursor:pointer;">Eliminar</button>` : '<span style="font-size:0.7rem; opacity:0.5;">Canal Base</span>'}
                    </div>
                `).join("")}
            </div>
            <button onclick="document.getElementById('AddChannelBtn').click()" class="PrimaryBtn" style="margin-top:20px;">+ Nuevo Canal</button>
        `;
    } else if (tab === 'srv-members') {
        renderMembersTab();
    } else if (tab === 'srv-bans') {
        renderBansTab();
    } else if (tab === 'srv-logs') {
        renderServerLogs();
    }
}

async function renderServerLogs() {
    try {
        const res = await fetch(`/api/servers/${currentServer.id}/logs`, { headers: { "Authorization": `Bearer ${token}` } });
        const logs = await res.json();
        const content = document.getElementById("SettingsContent");
        content.innerHTML = `
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
                <h2>Registro de Auditoría</h2>
                <div style="font-size:0.75rem; color:var(--text-muted);">Los últimos 100 eventos</div>
            </div>
            <div style="display:grid; gap:10px; max-height:500px; overflow-y:auto; padding-right:10px;">
                ${logs.map(l => `
                    <div class="LogItem" style="border-left: 3px solid var(--primary);">
                        <div style="display:flex; justify-content:space-between; font-size:0.65rem; color:var(--text-muted); margin-bottom:5px;">
                            <span>${new Date(l.timestamp).toLocaleString()}</span>
                            <span style="color:var(--primary); font-weight:800; background:rgba(16,185,129,0.1); padding:2px 6px; border-radius:4px;">${l.type}</span>
                        </div>
                        <div style="font-size:0.8rem; line-height:1.4; color:#fff;">
                            ${formatLogDetails(l)}
                        </div>
                    </div>
                `).join("") || "<div style='color:var(--text-muted); padding:40px; text-align:center;'>No hay actividad registrada en este servidor.</div>"}
            </div>
        `;
    } catch (e) {
        showToast("Error al cargar logs", "error");
    }
}

async function renderRolesTab() {
    const list = currentServer.roles || [];
    document.getElementById("SettingsContent").innerHTML = `
        <div class="SettingsHeader" style="display:flex; justify-content:space-between; align-items:center;">
            <h2>Roles y Permisos (${list.length})</h2>
            <button onclick="openCreateRoleModal()" class="PrimaryBtn" style="padding:6px 12px; font-size:0.8rem;">+ Nuevo Rol</button>
        </div>
        <div id="RoleList" style="margin-top:20px; display:grid; gap:10px;">
            ${list.map(r => {
                const isSystem = r.name === 'Owner' || r.name === '@everyone';
                return `
                <div class="LogItem" style="display:flex; justify-content:space-between; align-items:center; border-left: 4px solid ${r.color};">
                    <div>
                        <div style="display:flex; align-items:center; gap:8px;">
                            <div style="width:12px; height:12px; border-radius:50%; background:${r.color};"></div>
                            <span style="color:${r.color}; font-weight:800; font-size:1rem;">${r.name}</span>
                        </div>
                        <div style="font-size:0.65rem; color:var(--text-muted); margin-top:4px; max-width:350px;">
                            ${r.permissions.map(p => `<span style="background:rgba(255,255,255,0.05); padding:1px 4px; border-radius:3px; margin-right:4px;">${p}</span>`).join(" ")}
                        </div>
                    </div>
                    <div style="display:flex; gap:10px; align-items:center;">
                        ${!isSystem ? `<button onclick="openEditRoleModal('${r.id}')" title="Configurar Rol" style="background:transparent; border:none; color:var(--primary); font-size:1rem; cursor:pointer;">⚙️</button>` : ''}
                        ${!isSystem ? `<button onclick="deleteRole('${r.id}', '${r.name}')" title="Eliminar Rol" style="background:transparent; border:none; color:#ef4444; font-size:0.8rem; cursor:pointer; opacity:0.7;">Eliminar</button>` : ''}
                    </div>
                </div>
            `}).join("") || "<div style='color:var(--text-muted);'>No hay roles personalizados.</div>"}
        </div>
    `;
}

// Categorías de Permisos para el Editor
const PERM_CATEGORIES = {
    "General": ["ADMINISTRATOR", "MANAGE_SERVER", "VIEW_LOGS", "MANAGE_ROLES", "INVITE_USERS"],
    "Canales": ["CREATE_CHANNEL", "DELETE_CHANNEL", "VIEW_CHANNEL", "SEND_MESSAGES", "DELETE_MESSAGES", "PIN_MESSAGES"],
    "Miembros": ["KICK_MEMBERS", "BAN_MEMBERS", "MUTE_MEMBERS", "MANAGE_NICKNAMES"]
};

function openCreateRoleModal() {
    openRoleEditorModal(null);
}

function openEditRoleModal(roleId) {
    const role = currentServer.roles.find(r => r.id === roleId);
    openRoleEditorModal(role);
}

function openRoleEditorModal(role = null) {
    const isEdit = !!role;
    const title = isEdit ? `Editar Rol: ${role.name}` : "Crear Nuevo Rol";
    const btnText = isEdit ? "Guardar Cambios" : "Crear Rol";
    
    // Generar HTML de Permisos
    let permsHtml = "";
    for (const [cat, perms] of Object.entries(PERM_CATEGORIES)) {
        permsHtml += `<div style="margin-top:15px;"><strong style="font-size:0.75rem; color:var(--primary); text-transform:uppercase;">${cat}</strong><div style="display:grid; grid-template-columns:1fr 1fr; gap:8px; margin-top:8px;">`;
        perms.forEach(p => {
            const checked = role?.permissions.includes(p) ? 'checked' : '';
            permsHtml += `
            <label style="display:flex; align-items:center; gap:8px; font-size:0.75rem; cursor:pointer; color:var(--text-muted);">
                <input type="checkbox" value="${p}" ${checked} class="perm-checkbox" style="accent-color:var(--primary);">
                ${p.replace(/_/g, " ")}
            </label>`;
        });
        permsHtml += `</div></div>`;
    }

    const modalBody = `
        <div style="display:flex; flex-direction:column; gap:15px;">
            <div style="display:flex; gap:15px;">
                <div style="flex:2;">
                    <label style="display:block; font-size:0.7rem; color:var(--text-muted); margin-bottom:5px;">Nombre del Rol</label>
                    <input type="text" id="role-name-input" value="${role?.name || ''}" placeholder="Ej: Staff" class="AuthInput" style="padding:10px;">
                </div>
                <div style="flex:1;">
                    <label style="display:block; font-size:0.7rem; color:var(--text-muted); margin-bottom:5px;">Color</label>
                    <input type="color" id="role-color-input" value="${role?.color || '#10b981'}" style="width:100%; height:40px; border:none; background:transparent; cursor:pointer;">
                </div>
            </div>
            <div style="background:rgba(255,255,255,0.03); padding:15px; border-radius:10px; max-height:300px; overflow-y:auto; border:1px solid rgba(255,255,255,0.05);">
                <label style="display:block; font-size:0.7rem; color:var(--text-muted); margin-bottom:10px;">Permisos Granulares</label>
                ${permsHtml}
            </div>
        </div>
    `;

    openActionModal(
        title,
        modalBody,
        btnText,
        async () => {
            const name = document.getElementById("role-name-input").value.trim();
            const color = document.getElementById("role-color-input").value;
            const permissions = Array.from(document.querySelectorAll(".perm-checkbox:checked")).map(cb => cb.value);
            
            if (!name) throw new Error("Debes ponerle un nombre al rol");

            const url = isEdit ? `/api/servers/${currentServer.id}/roles/${role.id}` : `/api/servers/${currentServer.id}/roles`;
            const method = isEdit ? "PUT" : "POST";

            await safeFetch(url, {
                method,
                headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
                body: JSON.stringify({ name, color, permissions })
            });

            showToast(isEdit ? "Rol actualizado" : "Rol creado", "success");
            await selectServer(currentServer.id);
            switchSettingsTab('srv-roles');
        }
    );
}

async function createRole(name) {
    // Esta funcion ahora es reemplazada por openRoleEditorModal
}

async function deleteRole(roleId, name) {
    openActionModal(
        "Eliminar Rol",
        `¿Confirmas que quieres eliminar el rol '${name}'? Se quitará de todos los miembros.`,
        "Eliminar Rol",
        async () => {
            const res = await fetch(`/api/servers/${currentServer.id}/roles/${roleId}`, {
                method: "DELETE",
                headers: { "Authorization": `Bearer ${token}` }
            });
            if (res.ok) {
                showToast(`Rol ${name} eliminado`, "success");
                await selectServer(currentServer.id);
                switchSettingsTab('srv-roles');
            } else {
                const err = await res.json();
                throw new Error(err.error || "Error al eliminar");
            }
        }
    );
}

function formatLogDetails(l) {
    if (l.type === 'MEMBER_BANNED') return `@${l.targetUser} fue baneado por ${l.moderator}. Motivo: ${l.reason || 'Ninguno'}`;
    if (l.type === 'MEMBER_WARNED') return `@${l.targetUser} recibió una advertencia. Motivo: ${l.reason || 'Ninguno'}`;
    if (l.type === 'ROLE_CREATED') return `Rol '${l.roleName}' creado por ${l.creator}`;
    if (l.type === 'MEMBER_JOINED') return `@${l.username} se unió al servidor.`;
    return `Acción realizada por ${l.moderator || l.creator || l.username || 'System'}`;
}

async function renderBansTab() {
    const res = await fetch(`/api/servers/${currentServer.id}/bans`, { headers: { "Authorization": `Bearer ${token}` } });
    const bans = await res.json();
    document.getElementById("SettingsContent").innerHTML = `
        <h2 style="margin-bottom:20px;">Lista de Baneados</h2>
        <div style="display:grid; gap:10px;">
            ${bans.map(b => `
                <div class="LogItem" style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <div style="font-weight:800; color:#ef4444;">@${b.username}</div>
                        <div style="font-size:0.7rem; color:var(--text-muted);">Motivo: ${b.reason}</div>
                        <div style="font-size:0.6rem; color:var(--text-muted);">Por ${b.bannedBy} • Expira: ${b.expires ? new Date(b.expires).toLocaleDateString() : 'Nunca'}</div>
                    </div>
                    <button onclick="unbanUser('${b.username}')" style="background:var(--primary); color:#000; border:none; padding:4px 8px; border-radius:4px; font-size:0.75rem; font-weight:700;">Levantar</button>
                </div>
            `).join("") || "<div style='color:var(--text-muted);'>No hay baneados.</div>"}
        </div>
    `;
}

async function unbanUser(username) {
    const res = await fetch(`/api/servers/${currentServer.id}/bans/${username}`, { 
        method: "DELETE", 
        headers: { "Authorization": `Bearer ${token}` } 
    });
    if (res.ok) {
        showToast(`Baneo quitado a @${username}`, "success");
        renderBansTab();
    }
}

async function banMember(username) {
    openActionModal(
        `Banear a @${username}`,
        "Indica el motivo y duración (en días, 0 para permanente).",
        "Aplicar BAN",
        async (input) => {
            const [reason, days] = input.split(",").map(s => s.trim());
            const res = await fetch(`/api/servers/${currentServer.id}/members/${username}/ban`, {
                method: "POST",
                headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
                body: JSON.stringify({ reason: reason || "Sin motivo", days: parseInt(days) || 0 })
            });
            if (res.ok) {
                showToast(`@${username} ha sido baneado`, "error");
                closeProfile();
                await selectServer(currentServer.id);
            }
        },
        true,
        "Ej: Spam, 7"
    );
}

async function warnMember(username) {
    openActionModal(
        `Advertir a @${username}`,
        "Indica el motivo de la advertencia.",
        "Enviar Aviso",
        async (reason) => {
            const res = await fetch(`/api/servers/${currentServer.id}/members/${username}/warn`, {
                method: "POST",
                headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
                body: JSON.stringify({ reason })
            });
            if (res.ok) {
                showToast(`Advertencia enviada a @${username}`, "warning");
            }
        },
        true,
        "Motivo"
    );
}

function formatLogDetails(log) {
    const d = log.details || {};
    if (log.type === 'MEMBER_JOINED') return `El usuario <b style="color:#fff">@${d.username}</b> se unió usando el código <b style="color:var(--primary)">${d.inviteCode}</b>`;
    if (log.type === 'CHANNEL_CREATED') return `Canal <b style="color:#fff">#${d.channelName}</b> creado por <b style="color:#fff">@${d.creator}</b>`;
    if (log.type === 'CHANNEL_DELETED') return `Canal <b style="color:#fff">#${d.channelName}</b> eliminado por <b style="color:#fff">@${d.deletedBy}</b>`;
    if (log.type === 'SERVER_DELETED') return `Servidor eliminado por su dueño <b style="color:#fff">@${d.owner}</b>`;
    return JSON.stringify(d);
}

async function renderServerMembers() {
    if (!currentServer || currentTarget?.type === 'friend') return;
    
    try {
        const res = await fetch(`/api/servers/${currentServer.id}/members`, { headers: { "Authorization": `Bearer ${token}` } });
        const members = await res.json();
        const content = document.getElementById("MemberListContent");
        if (!content) return;
        
        const statusColors = { online: "#10b981", idle: "#f59e0b", dnd: "#ef4444", invisible: "#94a3b8", offline: "#4b5563" };
        const roles = [...(currentServer.roles || [])];
        
        // Asegurar que el rol "Everyone" o similar esté al final si existe, o crear "Miembros" si está vacío
        const everyoneIndex = roles.findIndex(r => r.name.toLowerCase() === '@everyone');
        let everyoneRole = { id: "default", name: "MIEMBROS", color: "#94a3b8" };
        if (everyoneIndex > -1) {
            everyoneRole = roles.splice(everyoneIndex, 1)[0];
        }

        const groups = {};
        roles.forEach(r => groups[r.id] = { role: r, members: [] });
        groups[everyoneRole.id] = { role: everyoneRole, members: [] };

        members.forEach(m => {
            // Asignar al primer rol que tenga el usuario que esté en nuestra lista de roles
            const bestRole = roles.find(r => m.roles?.includes(r.id)) || everyoneRole;
            groups[bestRole.id].members.push(m);
        });

        let html = "";
        [...roles, everyoneRole].forEach(role => {
            const group = groups[role.id];
            if (group && group.members.length > 0) {
                html += `<div class="MemberListHeader" style="color:${role.color}; margin-top:15px; font-size: 0.65rem;">${role.name.toUpperCase()} — ${group.members.length}</div>`;
                group.members.forEach(m => {
                    const status = m.status || 'offline';
                    const displayName = m.nickname || m.username;
                    html += `
                        <div class="MemberListItem" onclick="viewUserProfile('${m.username}')">
                            <div class="MemberAvatarSmall" style="background: linear-gradient(135deg, #2b2d31, #1e1f22); position:relative;">
                                <div style="position:absolute; bottom:-1px; right:-1px; width:10px; height:10px; border-radius:50%; background:${statusColors[status]}; border:2px solid #1e1f22;"></div>
                            </div>
                            <div class="MemberName" style="color: ${role.color}">${displayName}</div>
                        </div>
                    `;
                });
            }
        });

        content.innerHTML = html;
    } catch (e) { console.error("Error rendering members:", e); }
}

async function renderMembersTab() {
    const res = await fetch(`/api/servers/${currentServer.id}/members`, { headers: { "Authorization": `Bearer ${token}` } });
    const members = await res.json();
    const roles = currentServer.roles || [];
    
    // Verificar permisos del usuario actual para mostrar botones
    const myMember = members.find(m => m.username === currentUser.username);
    const hasModeration = currentServer.owner === currentUser.username || 
                        myMember?.roles.some(rid => {
                            const r = roles.find(x => x.id === rid);
                            return r?.permissions.includes("ADMINISTRATOR") || 
                                   r?.permissions.includes("KICK_MEMBERS") || 
                                   r?.permissions.includes("BAN_MEMBERS") || 
                                   r?.permissions.includes("MUTE_MEMBERS");
                        });

    document.getElementById("SettingsContent").innerHTML = `
        <div class="SettingsHeader"><h2>Miembros (${members.length})</h2></div>
        <div style="display:grid; gap:8px; margin-top:20px;">
            ${members.map(m => {
                const isOwner = m.username === currentServer.owner;
                const isMuted = m.isMuted;
                const status = m.status || 'offline';
                const statusColors = { online: "#10b981", idle: "#f59e0b", dnd: "#ef4444", invisible: "#94a3b8", offline: "#4b5563" };
                
                return `
                <div class="LogItemMember" style="display:flex; align-items:center; gap:12px; padding:12px; background:rgba(255,255,255,0.02); border:1px solid rgba(255,255,255,0.05); border-radius:8px;">
                    <div style="position:relative;">
                        <div class="UserAvatar" style="width:32px; height:32px; background:linear-gradient(45deg, ${isMuted ? '#6b7280' : '#10b981'}, ${isMuted ? '#374151' : '#059669'});"></div>
                        <div style="position:absolute; bottom:-2px; right:-2px; width:12px; height:12px; border-radius:50%; background:${statusColors[status]}; border:2px solid #1e1f22;"></div>
                    </div>
                    <div style="flex:1">
                        <div style="font-weight:700; color:#fff; font-size:0.9rem; display:flex; align-items:center; gap:5px;">
                            ${m.nickname || m.username} 
                            ${m.nickname ? `<span style="font-weight:400; color:var(--text-muted); font-size:0.75rem;">(@${m.username})</span>` : ''}
                            ${isMuted ? ' 🔇' : ''}
                            ${m.username === "Dev" ? '<span style="background:var(--primary); color:#000; font-size:0.6rem; padding:1px 4px; border-radius:4px; font-weight:900;">DEV</span>' : ''}
                        </div>
                        <div style="font-size:0.7rem; color:var(--text-muted)">ID: ${m.username.substring(0,8)}</div>
                    </div>
                    
                    <div style="display:flex; align-items:center; gap:10px;">
                        ${!isOwner && hasModeration ? `
                            <button onclick="openNicknameModal('${m.username}')" title="Cambiar Apodo" style="background:transparent; border:none; color:var(--text-muted); cursor:pointer;">✏️</button>
                            <button onclick="moderateMember('${m.username}', 'mute')" title="${isMuted ? 'Desmutear' : 'Mutear'}" style="background:transparent; border:none; color:${isMuted ? 'var(--primary)' : 'var(--text-muted)'}; cursor:pointer;">🔇</button>
                            <button onclick="moderateMember('${m.username}', 'kick')" title="Expulsar" style="background:transparent; border:none; color:#f59e0b; cursor:pointer;">👢</button>
                            <button onclick="moderateMember('${m.username}', 'ban')" title="Banear" style="background:transparent; border:none; color:#ef4444; cursor:pointer;">🚫</button>
                        ` : ''}
                        
                        ${isOwner ? `
                            <span class="RoleLabel" style="background:rgba(245,158,11,0.2); color:#f59e0b; border:1px solid rgba(245,158,11,0.3); padding:4px 10px; border-radius:4px; font-size:0.65rem; font-weight:800; text-transform:uppercase;">Owner</span>
                        ` : `
                            <select onchange="assignRole('${m.username}', this.value)" style="background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.1); color:#fff; font-size:0.7rem; padding:4px 8px; border-radius:4px; cursor:pointer;">
                                <option value="">Sin Rol</option>
                                ${roles.map(r => `<option value="${r.id}" ${m.roles?.includes(r.id) ? 'selected' : ''}>${r.name}</option>`).join("")}
                            </select>
                        `}
                    </div>
                </div>
            `}).join("")}
        </div>
    `;
}

async function moderateMember(username, action) {
    const titles = { mute: "¿Silenciar?", kick: "¿Expulsar?", ban: "¿Banear permanentemente?" };
    const messages = { 
        mute: `¿Confirmas que quieres silenciar/desilenciar a @${username}?`,
        kick: `¿Seguro que quieres expulsar a @${username} del servidor?`,
        ban: `¿CONFIRMAS EL BANEO PERMANENTE DE @${username}? Esta acción no se puede deshacer y el usuario no podrá volver.`
    };

    openActionModal(titles[action], messages[action], action.toUpperCase(), async () => {
        await safeFetch(`/api/servers/${currentServer.id}/members/${username}/${action}`, {
            method: "POST",
            headers: { "Authorization": `Bearer ${token}` }
        });
        showToast(`Acción ${action} ejecutada`, "success");
        renderMembersTab();
    });
}

function openNicknameModal(username) {
    openActionModal(
        "Cambiar Apodo",
        `Define un apodo personalizado para @${username} en este servidor.`,
        "Cambiar",
        async (nickname) => {
            await safeFetch(`/api/servers/${currentServer.id}/members/${username}/nickname`, {
                method: "PUT",
                headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
                body: JSON.stringify({ nickname })
            });
            showToast("Apodo actualizado", "success");
            renderMembersTab();
        },
        true,
        "Apodo (Dejar vacío para el original)"
    );
}

async function assignRole(username, roleId) {
    await safeFetch(`/api/servers/${currentServer.id}/members/${username}/roles`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
        body: JSON.stringify({ roleIds: [roleId] })
    });
    showToast(`Rol actualizado para @${username}`, "success");
    await selectServer(currentServer.id);
    renderMembersTab();
}


async function deleteCurrentServer() {
    openActionModal(
        "¿Eliminar Servidor?", 
        `Estás a punto de eliminar '${currentServer.name}' permanentemente. Esta acción no se puede deshacer y todos los datos se perderán para siempre.`,
        "ELIMINAR PERMANENTEMENTE",
        async () => {
            const res = await safeFetch(`/api/servers/${currentServer.id}`, {
                method: "DELETE",
                headers: { "Authorization": `Bearer ${token}` }
            });
            showToast("Servidor eliminado con éxito", "success");
            closeSettings();
            currentServer = null;
            loadServers();
            elements.channelList.innerHTML = "";
            elements.chatHeader.innerText = "Selecciona un servidor";
        }
    );
}

async function generateAdvancedInvite() {
    const maxUses = parseInt(document.getElementById("InvMaxUses").value);
    const expiresInMinutes = parseInt(document.getElementById("InvExpires").value);
    const res = await fetch(`/api/servers/${currentServer.id}/invites`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
        body: JSON.stringify({ maxUses: maxUses || null, expiresInMinutes: expiresInMinutes || null })
    });
    if (res.ok) {
        const invite = await res.json();
        
        // AUTO COPY TO CLIPBOARD (V7.0 Professional)
        try {
            const fullUrl = `${window.location.origin}/join?code=${invite.code}`;
            await navigator.clipboard.writeText(fullUrl);
            showToast(`Enlace de invitación copiado al portapapeles`, "success");
        } catch (e) {
            showToast(`Código generado: ${invite.code}`, "success");
        }
        
        await selectServer(currentServer.id);
        switchSettingsTab('srv-security');
    } else {
        const err = await res.json();
        throw new Error(err.error || "Error al generar invitación");
    }
}

async function deleteChannel(id, name) {
    openActionModal(
        "Eliminar Canal",
        `¿Confirmas la eliminación del canal #${name}? Todos los mensajes serán borrados.`,
        "Eliminar Canal",
        async () => {
            await safeFetch(`/api/servers/${currentServer.id}/channels/${id}`, {
                method: "DELETE",
                headers: { "Authorization": `Bearer ${token}` }
            });
            showToast(`Canal #${name} eliminado`, "success");
            await selectServer(currentServer.id);
            switchSettingsTab('srv-channels');
        }
    );
}

async function saveServerGeneral() {
    const name = document.getElementById("SetSrvName").value;
    const description = document.getElementById("SetSrvDesc").value;
    
    console.log(`[DEBUG] Guardando cambios para servidor: ${currentServer.id} a la URL: /api/servers/${currentServer.id}`);
    
    try {
        await safeFetch(`/api/servers/${currentServer.id}`, {
            method: "PUT",
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
            body: JSON.stringify({ name, description })
        });
        showToast("Servidor actualizado correctamente", "success");
        await loadServers(); // Recargar lista lateral
        await selectServer(currentServer.id); // Recargar vista actual
    } catch (e) {
        showToast(e.message, "error");
    }
}

// --- FRIENDS ---
async function loadFriends() {
    try {
        const res = await fetch("/api/friends", { headers: { "Authorization": `Bearer ${token}` } });
        const friends = await res.json();
        elements.friendsList.innerHTML = friends.map(f => `
            <div class="SocialItem ${currentTarget?.id === f.username ? 'active' : ''}" style="display:flex; justify-content:space-between; align-items:center;">
                <div onclick="selectTarget('${f.username}', 'friend', '${f.username}')" style="flex:1; display:flex; align-items:center; gap:8px;">
                    <div class="StatusDot ${f.status}"></div>
                    <span>@${f.username}</span>
                </div>
                <div style="display:flex; gap:5px;">
                    <span onclick="removeFriend('${f.username}')" title="Eliminar" style="cursor:pointer; font-size:0.8rem; opacity:0.5;">❌</span>
                    <span onclick="blockUser('${f.username}')" title="Bloquear" style="cursor:pointer; font-size:0.8rem; opacity:0.5;">🚫</span>
                </div>
            </div>
        `).join("");
    } catch (e) { console.error(e); }
}

async function removeFriend(username) {
    openActionModal(
        "Eliminar Amigo",
        `¿Confirmas que quieres eliminar a @${username} de tu lista de amigos?`,
        "Eliminar",
        async () => {
            const res = await fetch(`/api/friends/${username}`, { method: "DELETE", headers: { "Authorization": `Bearer ${token}` } });
            if (res.ok) {
                showToast("Amigo eliminado", "social");
                loadFriends();
            }
        }
    );
}

async function blockUser(username) {
    openActionModal(
        "Bloquear Usuario",
        `¿Seguro que quieres bloquear a @${username}? No podrá enviarte mensajes ni verte en línea.`,
        "Bloquear",
        async () => {
            const res = await fetch(`/api/friends/block`, { 
                method: "POST", 
                headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
                body: JSON.stringify({ username })
            });
            if (res.ok) {
                showToast("Usuario bloqueado", "error");
                loadFriends();
            }
        }
    );
}

function selectTarget(id, type, name) {
    currentTarget = { id, type, name };
    elements.chatHeader.innerText = type === 'channel' ? `# ${name}` : `@${id}`;
    
    const memberSide = document.getElementById("MemberListSide");
    if (memberSide) {
        if (type === 'friend') {
            memberSide.style.display = "none";
        } else {
            memberSide.style.display = "flex";
            renderServerMembers();
        }
    }
    
    loadMessages();
}

async function loadMessages() {
    if (!currentTarget) return;
    const type = currentTarget.type === 'channel' ? 'channel' : 'friend';
    const res = await fetch(`/api/messages/${type}/${currentTarget.id}`, { headers: { "Authorization": `Bearer ${token}` } });
    const messages = await res.json();
    elements.messageList.innerHTML = messages.map(m => {
        const time = m.timestamp ? new Date(m.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : (m.time || "");
        
        // Resolver Nickname y Color de Rol
        let displayName = m.sender;
        let roleColor = "var(--primary)";
        if (currentTarget.type === 'channel' && currentServer) {
            const member = currentServer.members?.find(mem => mem.username === m.sender);
            if (member) {
                displayName = member.nickname || member.username;
                const roleId = member.roles?.[0];
                const role = currentServer.roles?.find(r => r.id === roleId);
                if (role) roleColor = role.color;
            }
        }

        return `
            <div class="Message" style="margin-bottom:12px;">
                <div class="MessageHeader" style="display:flex; align-items:center; gap:8px;">
                    <span style="font-weight:800; color:${roleColor}; cursor:pointer" onclick="viewUserProfile('${m.sender}')">${displayName}</span>
                    <span style="font-size:0.65rem; color:var(--text-muted); opacity:0.7;">${time}</span>
                </div>
                <div class="MessageContent" style="margin-top:2px; font-size:0.95rem; line-height:1.4; color:#e5e7eb;">${m.text}</div>
            </div>
        `;
    }).join("");
    elements.messageList.scrollTop = elements.messageList.scrollHeight;
}

async function sendMessage() {
    const text = elements.chatInput.value.trim();
    if (!text || !currentTarget) return;
    elements.chatInput.value = "";
    
    // CORRECCIÓN: Enviar channelId si estamos en un canal, y el targetId debe ser el del servidor
    const body = { 
        targetId: currentTarget.type === 'channel' ? currentServer.id : currentTarget.id, 
        targetType: currentTarget.type === 'channel' ? 'server' : 'friend',
        channelId: currentTarget.type === 'channel' ? currentTarget.id : null,
        text 
    };

    const res = await fetch("/api/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
        body: JSON.stringify(body)
    });
    if (!res.ok) {
        const err = await res.json();
        showToast(err.error || "Error al enviar", "error");
    }
    loadMessages();
}

// --- EVENTS ---
function setupEventListeners() {
    elements.sendBtn.onclick = sendMessage;
    elements.chatInput.onkeypress = (e) => { if(e.key === 'Enter') sendMessage(); };
    
    // Selector de Estado
    const statusSel = document.getElementById("StatusSelector");
    if (statusSel) {
        statusSel.onchange = (e) => changeStatus(e.target.value);
    }

    document.getElementById("AddServerBtn").onclick = () => {
        openActionModal(
            "Crear un Servidor",
            "Tu servidor es donde tú y tus amigos pasáis el rato. Crea el tuyo y empieza a hablar.",
            "Crear Servidor",
            (name) => createServer(name),
            true,
            "Nombre del servidor"
        );
    };
    document.getElementById("JoinServerBtn").onclick = () => {
        openActionModal(
            "Unirse a un Servidor",
            "Introduce un código de invitación para unirte a un servidor existente.",
            "Unirse a Servidor",
            (code) => joinServer(code),
            true,
            "Código de invitación"
        );
    };
    document.getElementById("usernameDisplay").onclick = () => viewUserProfile(currentUser.username);
    
    // Vincular botón de añadir canal
    const addChannelBtn = document.getElementById("AddChannelBtn");
    if (addChannelBtn) {
        addChannelBtn.onclick = () => {
            openActionModal(
                "Crear Canal",
                "Los canales de texto son el lugar para hablar.",
                "Crear Canal",
                (name) => createChannel(name),
                true,
                "Nombre del canal"
            );
        };
    }
}

async function createChannel(name) {
    if (!currentServer) return;
    const res = await fetch(`/api/servers/${currentServer.id}/channels`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
        body: JSON.stringify({ name, type: "text" })
    });
    if (res.ok) {
        showToast(`Canal #${name} creado`, "success");
        selectServer(currentServer.id);
    } else {
        const err = await res.json();
        showToast(err.error || "Error al crear canal", "error");
    }
}

async function createServer(name) {
    try {
        const res = await fetch("/api/servers", { 
            method: "POST", 
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` }, 
            body: JSON.stringify({ name }) 
        });
        const data = await res.json();
        if (res.ok) {
            showToast(`Servidor "${name}" creado con éxito`, "success");
            loadServers();
        } else {
            showToast(data.error || "Error al crear servidor", "error");
        }
    } catch (e) {
        showToast("Error de conexión al crear servidor", "error");
    }
}

async function joinServer(code) {
    const res = await fetch("/api/invites/join", { 
        method: "POST", 
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` }, 
        body: JSON.stringify({ code }) 
    });
    if (res.ok) {
        showToast("Te has unido al servidor", "success");
        loadServers();
    } else {
        const err = await res.json();
        showToast(err.error || "Código inválido", "error");
    }
}

// --- SISTEMA DE LLAMADAS WebRTC "SUPER POTENTE" ---
let localStream;
let peerConnection;
const rtcConfig = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };

async function initCall(targetUser) {
    try {
        const overlay = document.getElementById("CallOverlay");
        overlay.style.display = "flex";
        
        localStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
        document.getElementById("localVideo").srcObject = localStream;
        
        setupPeerConnection(targetUser);
        
        const offer = await peerConnection.createOffer();
        await peerConnection.setLocalDescription(offer);
        
        await sendCallSignal(targetUser, offer);
        showToast(`Llamando a @${targetUser}...`, "info");
    } catch (err) {
        showToast("No se pudo acceder a la cámara/micro", "error");
        closeCall();
    }
}

function setupPeerConnection(targetUser) {
    peerConnection = new RTCPeerConnection(rtcConfig);
    
    localStream.getTracks().forEach(track => peerConnection.addTrack(track, localStream));
    
    peerConnection.ontrack = (event) => {
        document.getElementById("remoteVideo").srcObject = event.streams[0];
        document.getElementById("remoteName").innerText = targetUser;
    };
    
    peerConnection.onicecandidate = (event) => {
        if (event.candidate) {
            sendCallSignal(targetUser, { type: 'candidate', candidate: event.candidate });
        }
    };
}

async function sendCallSignal(target, signal) {
    await fetch("/api/calls/signal", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
        body: JSON.stringify({ target, signal })
    });
}

async function pollCallSignals() {
    if (!token) return;
    try {
        const res = await fetch("/api/calls/signal", { headers: { "Authorization": `Bearer ${token}` } });
        const signals = await res.json();
        for (const s of signals) {
            await handleCallSignal(s);
        }
    } catch (e) {}
    setTimeout(pollCallSignals, 3000);
}

async function handleCallSignal(data) {
    const { from, signal } = data;
    
    if (signal.type === 'offer') {
        if (confirm(`Videollamada entrante de @${from}. ¿Aceptar?`)) {
            const overlay = document.getElementById("CallOverlay");
            overlay.style.display = "flex";
            localStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
            document.getElementById("localVideo").srcObject = localStream;
            
            setupPeerConnection(from);
            await peerConnection.setRemoteDescription(new RTCSessionDescription(signal));
            const answer = await peerConnection.createAnswer();
            await peerConnection.setLocalDescription(answer);
            await sendCallSignal(from, answer);
        }
    } else if (signal.type === 'answer') {
        await peerConnection.setRemoteDescription(new RTCSessionDescription(signal));
    } else if (signal.type === 'candidate') {
        await peerConnection.addIceCandidate(new RTCIceCandidate(signal.candidate));
    }
}

function closeCall() {
    if (localStream) localStream.getTracks().forEach(t => t.stop());
    if (peerConnection) peerConnection.close();
    document.getElementById("CallOverlay").style.display = "none";
}

async function globalBanUser(username) {
    openActionModal(
        `Banear Global: @${username}`,
        "El usuario no podrá entrar a ninguna parte de la plataforma.",
        "Banear de NeutroLink",
        async (reason) => {
            const res = await fetch("/api/admin/global-ban", {
                method: "POST",
                headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
                body: JSON.stringify({ username, reason })
            });
            if (res.ok) showToast(`Usuario @${username} baneado globalmente`, "error");
        },
        true,
        "Motivo"
    );
}

async function globalWarnUser(username) {
    openActionModal(
        `Advertencia Global: @${username}`,
        "El usuario recibirá una notificación de advertencia de la plataforma.",
        "Enviar Aviso",
        async (reason) => {
            const res = await fetch("/api/admin/global-warn", {
                method: "POST",
                headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
                body: JSON.stringify({ username, reason })
            });
            if (res.ok) showToast(`Aviso global enviado a @${username}`, "info");
        },
        true,
        "Motivo"
    );
}

async function setStaffMember(username, isAdmin) {
    const res = await fetch("/api/admin/set-staff", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
        body: JSON.stringify({ username, isAdmin })
    });
    if (res.ok) {
        showToast(`Estado de Staff actualizado para @${username}`, "success");
        showAdminPanel(); // Refresh
    }
}

function showAdminPanel() {
    currentServer = null; 
    currentTarget = null;
    elements.chatHeader.innerText = "Panel de Control Maestro (Discord Corp Style)";
    elements.messageList.innerHTML = `
        <div style="padding: 20px;">
            <h2 style="color:var(--primary); text-shadow: 0 0 10px var(--primary);">Administración Superior NeutroLink</h2>
            <p style="color: var(--text-muted); margin-bottom: 25px;">Poder absoluto sobre la infraestructura y usuarios.</p>
            
            <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap:20px;">
                <div class="LogItem" style="background:rgba(239, 68, 68, 0.05); border: 2px solid #ef4444; border-radius: 12px; padding: 20px;">
                    <h3 style="color:#ef4444;">Baneo Global</h3>
                    <p style="font-size:0.85rem; margin:10px 0; color:var(--text-muted);">Elimina a un usuario de toda la plataforma de forma permanente.</p>
                    <button class="PrimaryBtn" style="background:#ef4444; color:#fff; width:100%; border-radius:8px;" onclick="openActionModal('Baneo Global', 'Introduce el username exacto', 'Banear', (u) => globalBanUser(u), true, 'Username')">Ejecutar Ban</button>
                </div>
                
                <div class="LogItem" style="background:rgba(245, 158, 11, 0.05); border: 2px solid #f59e0b; border-radius: 12px; padding: 20px;">
                    <h3 style="color:#f59e0b;">Advertencia Global</h3>
                    <p style="font-size:0.85rem; margin:10px 0; color:var(--text-muted);">Envía un aviso oficial a cualquier usuario por mal comportamiento.</p>
                    <button class="PrimaryBtn" style="background:#f59e0b; color:#fff; width:100%; border-radius:8px;" onclick="openActionModal('Advertencia Global', 'Introduce el username', 'Advertir', (u) => globalWarnUser(u), true, 'Username')">Enviar Aviso</button>
                </div>

                <div class="LogItem" style="background:rgba(16, 185, 129, 0.05); border: 2px solid #10b981; border-radius: 12px; padding: 20px; grid-column: 1 / -1;">
                    <h3 style="color:#10b981;">Gestionar Staff de Confianza</h3>
                    <p style="font-size:0.85rem; margin:10px 0; color:var(--text-muted);">Asigna o retira poderes de administración global a otros usuarios.</p>
                    <div style="display:flex; gap:10px; margin-top:15px;">
                        <input type="text" id="StaffTargetInput" placeholder="Username del futuro Staff" class="AuthInput" style="flex:1;">
                        <button class="PrimaryBtn" style="background:#10b981; color:#000; padding:0 20px;" onclick="setStaffMember(document.getElementById('StaffTargetInput').value, true)">Añadir Staff</button>
                        <button class="DangerBtn" style="background:#ef4444; color:#fff; padding:0 20px;" onclick="setStaffMember(document.getElementById('StaffTargetInput').value, false)">Quitar Staff</button>
                    </div>
                </div>
            </div>
        </div>
    `;
}

document.getElementById("HangupBtn").onclick = closeCall;
pollCallSignals();
