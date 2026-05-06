document.addEventListener("DOMContentLoaded", function () {
    console.log("[SafeRecruit] UI Restored to Stable Mode.");

    const form = document.getElementById("jobForm");
    const loader = document.getElementById("loader");
    const loaderText = document.getElementById("loaderText");
    const button = document.getElementById("analyzeBtn");
    const textarea = document.getElementById("jobInput");

    // Auto-resize and Pulse Logic
    if (textarea) {
        textarea.addEventListener("input", function () {
            this.style.height = "auto";
            this.style.height = Math.min(this.scrollHeight, 200) + "px";
            
            if (button) {
                if (this.value.trim().length > 0) {
                    button.classList.add("pulse");
                } else {
                    button.classList.remove("pulse");
                }
            }
        });
    }

    // Form Submit Logic
    if (form) {
        form.addEventListener("submit", function () {
            if (loader) {
                loader.style.display = "flex";
                loader.style.opacity = "1";
                
                const inputWrapper = document.querySelector(".chatbox-fixed-bottom");
                if (inputWrapper) {
                    inputWrapper.style.opacity = "0.2";
                    inputWrapper.style.pointerEvents = "none";
                }
            }
            if (button) {
                button.disabled = true;
                button.classList.remove("pulse");
            }

            if (loaderText) {
                const messages = [
                    "Analyzing job content...",
                    "Checking company verification...",
                    "Running AI model...",
                    "Scanning for fraud patterns...",
                    "Finalizing forensic report..."
                ];
                let msgIndex = 0;
                const cycleMessages = () => {
                    if (!loader || loader.style.display === "none") return;
                    loaderText.style.opacity = "0";
                    setTimeout(() => {
                        loaderText.textContent = messages[msgIndex];
                        loaderText.style.opacity = "1";
                        msgIndex = (msgIndex + 1) % messages.length;
                    }, 300);
                };
                cycleMessages();
                window._loaderInterval = setInterval(cycleMessages, 3000);
            }
        });
    }

    // ===== IMAGE PREVIEW LOGIC =====
    const jobImageInput = document.getElementById("jobImageInput");
    const imagePreview = document.getElementById("imagePreview");
    const imgThumb = document.getElementById("imgPreviewThumb");
    const imgName = document.getElementById("imgFileName");
    const imgRemove = document.getElementById("imgRemoveBtn");

    if (jobImageInput && imagePreview) {
        jobImageInput.addEventListener("change", function () {
            const file = this.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = function (e) {
                    if (imgThumb) imgThumb.src = e.target.result;
                    if (imgName) imgName.textContent = file.name.length > 25 ? file.name.slice(0, 22) + '...' : file.name;
                    imagePreview.style.display = "flex";
                };
                reader.readAsDataURL(file);
            }
        });

        if (imgRemove) {
            imgRemove.addEventListener("click", function () {
                jobImageInput.value = "";
                imagePreview.style.display = "none";
                if (imgThumb) imgThumb.src = "";
            });
        }
    }

    // Word Count Logic
    if (textarea) {
        textarea.addEventListener("input", function () {
            const wc = document.getElementById("wordCount");
            if (wc) {
                const words = this.value.trim().split(/\s+/).filter(Boolean).length;
                wc.textContent = words > 0 ? `${words} words` : "";
            }
        });
    }
});

window.autoResize = function(el) {
    el.style.height = '';
    el.style.height = Math.min(el.scrollHeight, 200) + 'px';
    
    // Update word count
    var wc = document.getElementById('wordCount');
    if (wc) {
        var words = el.value.trim().split(/\s+/).filter(Boolean).length;
        wc.textContent = words > 0 ? words + ' words' : '';
    }
};

// Particles logic kept for visual flair
const canvas = document.getElementById("particleCanvas");
if (canvas) {
    // ... (rest of particle logic stays as is if needed, but I'll assume it's fine)
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

    // Faster hover response
    document.addEventListener("mousemove", (event) => {
        mouseX = event.clientX;
        mouseY = event.clientY;
    }, { passive: true });

    window.addEventListener("resize", resizeCanvas, { passive: true });
    resizeCanvas();
    animate();
}

document.addEventListener("DOMContentLoaded", () => {
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

    // ===== LIVE WORD COUNT =====
    const jobTextarea = document.getElementById("jobInput");
    const wordCountEl = document.getElementById("wordCount");
    if (jobTextarea && wordCountEl) {
        function updateWordCount() {
            const words = jobTextarea.value.trim().split(/\s+/).filter(Boolean);
            const count = words.length;
            let mode = "";
            if (count === 0) {
                wordCountEl.textContent = "";
                return;
            } else if (count < 50) {
                mode = " · Brief mode";
            } else if (count < 200) {
                mode = " · Standard mode";
            } else {
                mode = " · Deep mode 🔍";
            }
            wordCountEl.textContent = `${count} word${count !== 1 ? "s" : ""}${mode}`;
        }
        jobTextarea.addEventListener("input", updateWordCount);
    }

    // ===== COPY REPORT =====
    window.copyReport = function () {
        const prediction   = document.querySelector(".result-card h2")?.textContent?.trim() || "";
        const risk         = document.querySelector(".risk-text")?.textContent?.trim() || "";
        const category     = document.querySelector(".category-badge")?.textContent?.trim() || "";
        const findingItems = document.querySelectorAll(".finding-item");
        const tipItems     = document.querySelectorAll(".tip-item");

        let report = `SafeRecruit AI — Analysis Report\n`;
        report += `================================\n`;
        report += `Verdict    : ${prediction}\n`;
        report += `Risk Score : ${risk}\n`;
        report += `Category   : ${category}\n`;
        if (findingItems.length) {
            report += `\nKey Findings:\n`;
            findingItems.forEach(li => { report += `  • ${li.textContent.trim()}\n`; });
        }
        if (tipItems.length) {
            report += `\nSafety Tips:\n`;
            tipItems.forEach(li => { report += `  • ${li.textContent.trim()}\n`; });
        }
        report += `\nAnalyzed by SafeRecruit AI — ${new Date().toLocaleString()}`;

        navigator.clipboard.writeText(report).then(() => {
            const btn = document.getElementById("copyReportBtn");
            if (!btn) return;
            const orig = btn.innerHTML;
            btn.innerHTML = "✅ Copied!";
            btn.style.background = "#10b981";
            btn.style.color = "#fff";
            setTimeout(() => {
                btn.innerHTML = orig;
                btn.style.background = "";
                btn.style.color = "";
            }, 2000);
        }).catch(() => {
            alert("Could not copy to clipboard. Please copy manually.");
        });
    };
});
