// profile.js

document.addEventListener("DOMContentLoaded", async () => {
    const token = localStorage.getItem("token");
    if (!token) {
        window.location.href = "/index.html";
        return;
    }

    try {
        const res = await fetch("/api/profile", {
            headers: { "Authorization": `Bearer ${token}` }
        });

        if (!res.ok) throw new Error("Sesión inválida");

        const data = await res.json();
        document.getElementById("usernameDisplay").innerText = data.username;
    } catch (e) {
        console.error(e);
        localStorage.removeItem("token");
        window.location.href = "/index.html";
    }

    document.getElementById("LogoutBtn").addEventListener("click", () => {
        localStorage.removeItem("token");
        window.location.href = "/index.html";
    });
});