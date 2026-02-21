// Elements
const viewSubtitle = document.getElementById("ViewSubtitle");
const loginBtn = document.getElementById("LoginBtn");
const registerBtn = document.getElementById("RegisterBtn");
const switchBtn = document.getElementById("SwitchToRegister");
const viewToggle = document.getElementById("ViewToggle");

// Toast System
const createToastContainer = () => {
    let container = document.getElementById("toast-container");
    if (!container) {
        container = document.createElement("div");
        container.id = "toast-container";
        document.body.appendChild(container);
    }
    return container;
};

function showToast(message, type = "success") {
    const container = createToastContainer();
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    
    const icon = type === "success" ? "✅" : type === "error" ? "❌" : "⚠️";
    
    toast.innerHTML = `
        <span>${icon}</span>
        <div class="toast-content">${message}</div>
        <div class="toast-progress">
            <div class="toast-progress-fill"></div>
        </div>
    `;

    container.appendChild(toast);

    const progressFill = toast.querySelector(".toast-progress-fill");
    progressFill.style.transition = "transform 3s linear";
    progressFill.style.transform = "scaleX(1)";
    setTimeout(() => { progressFill.style.transform = "scaleX(0)"; }, 10);

    setTimeout(() => {
        toast.classList.add("fade-out");
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

let isRegisterMode = false;

// UI Interactions
const toggleView = () => {
    isRegisterMode = !isRegisterMode;
    
    if (isRegisterMode) {
        viewSubtitle.innerText = "Crea una cuenta para comenzar tu experiencia.";
        loginBtn.classList.add("hidden");
        registerBtn.classList.remove("hidden");
        viewToggle.innerHTML = '¿Ya tienes una cuenta? <button class="ToggleBtn" id="SwitchToLogin">Inicia Sesión</button>';
        document.getElementById("SwitchToLogin").addEventListener("click", toggleView);
    } else {
        viewSubtitle.innerText = "Bienvenido de nuevo. Por favor, ingresa tus credenciales.";
        loginBtn.classList.remove("hidden");
        registerBtn.classList.add("hidden");
        viewToggle.innerHTML = '¿No tienes una cuenta? <button class="ToggleBtn" id="SwitchToRegister">Regístrate</button>';
        document.getElementById("SwitchToRegister").addEventListener("click", toggleView);
    }
};

switchBtn.addEventListener("click", toggleView);

// API Calls
async function handleAction(endpoint, body) {
    const originalBtnText = isRegisterMode ? registerBtn.innerText : loginBtn.innerText;
    const activeBtn = isRegisterMode ? registerBtn : loginBtn;
    
    try {
        activeBtn.innerText = "Procesando...";
        activeBtn.disabled = true;

        const res = await fetch(`/${endpoint}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body)
        });

        const data = await res.json();

        if (res.ok) {
            if (endpoint === "login" && data.token) {
                localStorage.setItem("token", data.token);
                showToast("¡Éxito! Bienvenido a NeutroLink", "success");
                setTimeout(() => window.location.href = "/profile.html", 1500);
            } else {
                showToast(data.message || "Operación exitosa", "success");
                if (isRegisterMode) toggleView();
            }
        } else {
            throw new Error(data.error || "Ocurrió un error inesperado");
        }
    } catch (err) {
        showToast(err.message, "error");
    } finally {
        activeBtn.innerText = originalBtnText;
        activeBtn.disabled = false;
    }
}

loginBtn.addEventListener("click", () => {
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    if (!username || !password) return showToast("Por favor completa todos los campos", "warning");
    handleAction("login", { username, password });
});

registerBtn.addEventListener("click", () => {
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    if (!username || !password) return showToast("Por favor completa todos los campos", "warning");
    handleAction("register", { username, password });
});

