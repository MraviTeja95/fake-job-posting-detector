// ==========================
// Elements
// ==========================
const form = document.getElementById("jobForm");
const loader = document.getElementById("loader");
const button = document.getElementById("analyzeBtn");
const textarea = document.querySelector("textarea");
const fileInput = document.getElementById("fileUpload");

// ==========================
// Loading Animation
// ==========================
if (form) {
    form.addEventListener("submit", function () {

        loader.style.display = "block";

        button.disabled = true;
        button.innerText = "Analyzing...";

        if (fileInput && fileInput.files.length > 0) {
            loader.innerText = "Extracting text from screenshot...";
        } 
        else if (textarea && textarea.value.includes("linkedin.com")) {
            loader.innerText = "Scanning LinkedIn profile...";
        } 
        else {
            loader.innerText = "Analyzing job description...";
        }
    });
}

// ==========================
// File Upload UI
// ==========================
if (fileInput) {

    fileInput.addEventListener("change", function () {

        const fileName = this.files[0]?.name;

        if (fileName) {
            document.querySelector(".upload-box p").innerText = fileName;

            document.querySelector(".upload-box").style.borderColor = "#22c55e";
            document.querySelector(".upload-box").style.boxShadow = "0 0 20px rgba(34,197,94,0.4)";
        }
    });
}

// ==========================
// Mouse Glow Effect
// ==========================
let mouseX = window.innerWidth / 2;
let mouseY = window.innerHeight / 2;

document.addEventListener("mousemove", (e) => {
    mouseX = e.clientX;
    mouseY = e.clientY;
});

// ==========================
// Meter Animation
// ==========================
window.addEventListener("load", () => {

    const meter = document.querySelector(".meter-bar");

    if (meter) {
        let finalWidth = meter.style.width;
        meter.style.width = "0%";

        setTimeout(() => {
            meter.style.width = finalWidth;
        }, 300);
    }
});

// ==========================
// Particle Background
// ==========================
const canvas = document.getElementById("particleCanvas");

if (canvas) {

    const ctx = canvas.getContext("2d");

    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    let particles = [];
    const particleCount = 100;

    class Particle {
        constructor() {
            this.x = Math.random() * canvas.width;
            this.y = Math.random() * canvas.height;
            this.vx = (Math.random() - 0.5) * 1;
            this.vy = (Math.random() - 0.5) * 1;
        }

        move() {
            this.x += this.vx;
            this.y += this.vy;

            if (this.x < 0 || this.x > canvas.width) this.vx *= -1;
            if (this.y < 0 || this.y > canvas.height) this.vy *= -1;
        }

        draw() {
            ctx.beginPath();
            ctx.arc(this.x, this.y, 2, 0, Math.PI * 2);
            ctx.fillStyle = "rgba(0, 0, 0, 0.4)";
            ctx.fill();

            let dx = this.x - mouseX;
            let dy = this.y - mouseY;
            let distance = Math.sqrt(dx * dx + dy * dy);

            if (distance < 150) {
                ctx.beginPath();
                ctx.arc(this.x, this.y, 2.5, 0, Math.PI * 2);
                ctx.fillStyle = `rgba(0, 0, 0, ${(1 - distance / 150) * 0.6})`;
                ctx.fill();
            }
        }
    }

    for (let i = 0; i < particleCount; i++) {
        particles.push(new Particle());
    }

    function connectParticles() {
        for (let i = 0; i < particles.length; i++) {
            for (let j = i; j < particles.length; j++) {
                let dx = particles[i].x - particles[j].x;
                let dy = particles[i].y - particles[j].y;
                let distance = Math.sqrt(dx * dx + dy * dy);

                if (distance < 120) {
                    ctx.beginPath();
                    ctx.strokeStyle = "rgba(0, 0, 0, 0.1)";
                    ctx.lineWidth = 1;
                    ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.stroke();
                }
            }
        }
    }

    function animate() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        particles.forEach(p => {
            p.move();
            p.draw();
        });

        connectParticles();
        requestAnimationFrame(animate);
    }

    animate();

    window.addEventListener("resize", () => {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    });
}

// ==========================
// AI Typing Effect
// ==========================
window.addEventListener("load", () => {

    const items = document.querySelectorAll(".analysis-item");

    if (items.length === 0) return;

    let delay = 500;

    items.forEach((item) => {
        const text = item.dataset.text;

        setTimeout(() => {
            typeText(item, text, 0);
        }, delay);

        delay += text.length * 35 + 400;
    });
});

function typeText(element, text, i) {
    if (i < text.length) {
        element.innerHTML += text.charAt(i);

        setTimeout(() => {
            typeText(element, text, i + 1);
        }, 20);
    }
}
function toggleMenu() {
    const menu = document.getElementById("profileMenu");
    menu.style.display = menu.style.display === "block" ? "none" : "block";
}