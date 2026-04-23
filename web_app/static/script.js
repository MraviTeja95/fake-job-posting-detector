const form = document.getElementById("jobForm");
const loader = document.getElementById("loader");
const loaderText = document.getElementById("loaderText");
const button = document.getElementById("analyzeBtn");
const textarea = document.getElementById("jobInput");
const fileInput = document.getElementById("fileUpload");
const btnText = document.getElementById("btnText");
const btnLoader = document.getElementById("btnLoader");

function setButtonLoading(btn, text) {
    if (!btn) return;

    const loadingText = text || btn.dataset.loadingText || "Working...";
    btn.dataset.originalText = btn.dataset.originalText || btn.innerHTML;
    btn.textContent = loadingText;
    btn.disabled = true;
}

if (form) {
    form.addEventListener("submit", function () {
        if (loader) loader.style.display = "block";
        if (button) button.disabled = true;
        if (btnText) btnText.style.display = "none";
        if (btnLoader) btnLoader.style.display = "inline-flex";

        if (loaderText) {
            const hasFile = fileInput && fileInput.files.length > 0;
            const textValue = (textarea?.value || "").toLowerCase();

            if (hasFile) {
                loaderText.textContent = "Extracting text from screenshot...";
            } else if (textValue.includes("linkedin.com")) {
                loaderText.textContent = "Scanning LinkedIn profile...";
            } else {
                loaderText.textContent = "Analyzing job description...";
            }
        }
    });
}

if (fileInput) {
    const uploadP = document.querySelector(".upload-text p");
    const uploadBox = document.querySelector(".upload-box");
    const defaultUploadText = uploadP?.textContent || "Upload Screenshot";

    fileInput.addEventListener("change", function () {
        const fileName = this.files[0]?.name;

        if (uploadP) uploadP.textContent = fileName || defaultUploadText;
        if (uploadBox) uploadBox.classList.toggle("is-selected", Boolean(fileName));
    });
}

document.querySelectorAll("form").forEach((pageForm) => {
    if (pageForm.id === "jobForm") return;

    pageForm.addEventListener("submit", function () {
        const submitButton = pageForm.querySelector("button[type='submit']");
        setButtonLoading(submitButton);
    });
});

function setProfileMenu(open, trigger) {
    const menu = document.getElementById("profileMenu");
    const profileButton = trigger || document.querySelector(".profile-box");

    if (!menu) return;

    menu.classList.toggle("active", open);
    if (profileButton) profileButton.setAttribute("aria-expanded", String(open));
}

window.toggleMenu = function (trigger) {
    const menu = document.getElementById("profileMenu");
    if (!menu) return;

    const isOpen = menu.classList.contains("active");
    setProfileMenu(!isOpen, trigger);
};

document.addEventListener("click", function (event) {
    if (!event.target.closest(".profile-wrapper")) {
        setProfileMenu(false);
    }
});

document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") {
        setProfileMenu(false);
    }
});

window.addEventListener("load", () => {
    const meter = document.querySelector(".meter-bar");
    if (!meter) return;

    const finalWidth = meter.style.width;
    meter.style.width = "0%";

    requestAnimationFrame(() => {
        window.setTimeout(() => {
            meter.style.width = finalWidth;
        }, 180);
    });
});

const canvas = document.getElementById("particleCanvas");
const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

if (canvas && !reduceMotion) {
    const ctx = canvas.getContext("2d");
    let mouseX = window.innerWidth / 2;
    let mouseY = window.innerHeight / 2;
    let particles = [];

    class Particle {
        constructor() {
            this.reset(true);
        }

        reset(randomizePosition) {
            this.x = randomizePosition ? Math.random() * window.innerWidth : window.innerWidth / 2;
            this.y = randomizePosition ? Math.random() * window.innerHeight : window.innerHeight / 2;
            this.vx = (Math.random() - 0.5) * 0.45;
            this.vy = (Math.random() - 0.5) * 0.45;
            this.size = 1.2 + Math.random() * 1.5;
            this.alpha = 0.18 + Math.random() * 0.22;
        }

        move() {
            this.x += this.vx;
            this.y += this.vy;

            if (this.x < -20) this.x = window.innerWidth + 20;
            if (this.x > window.innerWidth + 20) this.x = -20;
            if (this.y < -20) this.y = window.innerHeight + 20;
            if (this.y > window.innerHeight + 20) this.y = -20;
        }

        draw(pColor, pGlow) {
            const dx = this.x - mouseX;
            const dy = this.y - mouseY;
            const dist = Math.sqrt(dx * dx + dy * dy);
            const lift = dist < 150 ? (1 - dist / 150) * 0.35 : 0;

            ctx.beginPath();
            ctx.arc(this.x, this.y, this.size + lift, 0, Math.PI * 2);

            ctx.fillStyle = `rgba(${pColor}, ${this.alpha + lift})`;
            ctx.shadowBlur = pGlow;
            if (pGlow > 0) ctx.shadowColor = `rgba(${pColor}, 0.6)`;

            ctx.fill();
            ctx.shadowBlur = 0;
        }
    }

    function resizeCanvas() {
        const ratio = Math.min(window.devicePixelRatio || 1, 2);
        canvas.width = Math.floor(window.innerWidth * ratio);
        canvas.height = Math.floor(window.innerHeight * ratio);
        canvas.style.width = `${window.innerWidth}px`;
        canvas.style.height = `${window.innerHeight}px`;
        ctx.setTransform(ratio, 0, 0, ratio, 0, 0);

        const particleCount = Math.max(48, Math.min(110, Math.floor(window.innerWidth * window.innerHeight / 16000)));
        particles = Array.from({ length: particleCount }, () => new Particle());
    }

    function connectParticles(pColor, pGlow) {
        for (let i = 0; i < particles.length; i++) {
            for (let j = i + 1; j < particles.length; j++) {
                const dx = particles[i].x - particles[j].x;
                const dy = particles[i].y - particles[j].y;
                const dist = Math.sqrt(dx * dx + dy * dy);

                if (dist < 118) {
                    ctx.beginPath();
                    ctx.strokeStyle = `rgba(${pColor}, ${(1 - dist / 118) * 0.15})`;
                    ctx.lineWidth = 1;

                    if (pGlow > 0) {
                        ctx.shadowBlur = pGlow / 2;
                        ctx.shadowColor = `rgba(${pColor}, 0.4)`;
                    } else {
                        ctx.shadowBlur = 0;
                    }

                    ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.stroke();
                }
            }
        }
    }

    let cachedPColor = '23, 23, 23';
    let cachedPGlow = 0;
    let frameCount = 0;

    function animate() {
        if (frameCount % 30 === 0) {
            const styles = getComputedStyle(document.documentElement);
            cachedPColor = styles.getPropertyValue('--particle-color').trim() || '23, 23, 23';
            cachedPGlow = parseInt(styles.getPropertyValue('--particle-glow').trim() || '0');
        }
        frameCount++;

        ctx.clearRect(0, 0, window.innerWidth, window.innerHeight);
        particles.forEach((particle) => {
            particle.move();
            particle.draw(cachedPColor, cachedPGlow);
        });
        connectParticles(cachedPColor, cachedPGlow);
        requestAnimationFrame(animate);
    }

    document.addEventListener("mousemove", (event) => {
        mouseX = event.clientX;
        mouseY = event.clientY;
    });

    window.addEventListener("resize", resizeCanvas);
    resizeCanvas();
    animate();
}

// Theme Selector Logic
document.addEventListener("DOMContentLoaded", () => {
    const themeSelector = document.getElementById("themeSelector");

    if (!themeSelector) return;

    // Check localStorage for theme
    const currentTheme = localStorage.getItem("theme") || "light";
    if (currentTheme !== "light") {
        document.documentElement.setAttribute("data-theme", currentTheme);
    }
    themeSelector.value = currentTheme;

    themeSelector.addEventListener("change", (e) => {
        const theme = e.target.value;
        if (theme === "light") {
            document.documentElement.removeAttribute("data-theme");
        } else {
            document.documentElement.setAttribute("data-theme", theme);
        }
        localStorage.setItem("theme", theme);
    });

    // History Filter Logic
    const historySearch = document.getElementById("historySearch");
    const historyFilter = document.getElementById("historyFilter");
    const historyItems = document.querySelectorAll(".history-item");

    function filterHistory() {
        if (!historySearch || !historyFilter) return;

        const searchTerm = historySearch.value.toLowerCase();
        const filterType = historyFilter.value;

        historyItems.forEach(item => {
            const textContent = item.textContent.toLowerCase();
            const predictionBadge = item.querySelector(".prediction-badge").textContent.toUpperCase();

            const matchesSearch = textContent.includes(searchTerm);
            const matchesType = filterType === "ALL" || predictionBadge === filterType;

            if (matchesSearch && matchesType) {
                item.style.display = "block";
            } else {
                item.style.display = "none";
            }
        });
    }

    if (historySearch) historySearch.addEventListener("input", filterHistory);
    if (historyFilter) historyFilter.addEventListener("change", filterHistory);
});
