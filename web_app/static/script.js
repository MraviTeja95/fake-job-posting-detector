document.addEventListener("DOMContentLoaded", function () {
    console.log("[SafeRecruit] UI Restored to Stable Mode.");
    if (typeof initWaveBackground === "function") {
        initWaveBackground();
    }

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

    // Form Submit Logic — DOES NOT block form submission (no preventDefault)
    if (form) {
        form.addEventListener("submit", function () {
            console.log("[SafeRecruit] Form submitting...");
            console.log("[SafeRecruit] Has text:", textarea ? textarea.value.trim().length > 0 : false);

            var fileInput = document.getElementById("jobImageInput");
            console.log("[SafeRecruit] Has image:", fileInput && fileInput.files.length > 0);
            if (fileInput && fileInput.files.length > 0) {
                console.log("[SafeRecruit] Image name:", fileInput.files[0].name);
                console.log("[SafeRecruit] Image size:", fileInput.files[0].size, "bytes");
            }

            // Show loader overlay
            if (loader) {
                loader.style.display = "flex";
                loader.style.opacity = "1";
            }
            // Disable button to prevent double-submit
            if (button) {
                button.disabled = true;
                button.classList.remove("pulse");
                button.classList.add("is-loading");
                button.setAttribute("aria-busy", "true");
            }

            // Cycle status messages
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

            // DO NOT return false or call preventDefault — let the form submit normally
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
                const allowed = ["image/png", "image/jpeg", "image/webp"];
                if (!allowed.includes(file.type) || file.size > 8 * 1024 * 1024) {
                    alert("Please upload a PNG, JPG, JPEG, or WEBP screenshot under 8 MB.");
                    this.value = "";
                    imagePreview.style.display = "none";
                    if (imgThumb) imgThumb.src = "";
                    if (imgName) imgName.textContent = "";
                    return;
                }
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


document.querySelectorAll("form").forEach((pageForm) => {
    if (pageForm.id === "jobForm") return;

    pageForm.addEventListener("submit", function () {
        const submitButton = pageForm.querySelector("button[type='submit']");
        if (typeof setButtonLoading === "function") {
            setButtonLoading(submitButton);
        }
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

// ===== 3D Three.js Dotted Wave Background =====
// Renders a premium, interactive animated wave of particles in the background.
// Customizations:
// - Grid dimensions (density): Change AMOUNTX / AMOUNTY
// - Wave height / speed: Adjust count step (0.025) and wave multiplier (60)
// - Colors: Configured via CSS variables or falls back to custom themes
window.initWaveBackground = function() {
    const canvas = document.getElementById("waveCanvas");
    if (!canvas) return;

    console.log("Wave background initialized");

    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduceMotion) return;

    function startAnimation() {
        const THREE = window.THREE;
        if (!THREE) return;

        const SEPARATION = 140;
        const AMOUNTX = 45; 
        const AMOUNTY = 45;

        let scene, camera, renderer, particles, geometry, material;
        let count = 0;
        let animationId;

        // Initialize Scene — light premium white theme
        scene = new THREE.Scene();
        scene.background = new THREE.Color(0xffffff);
        scene.fog = new THREE.Fog(0xffffff, 2000, 10000);

        // Camera positioning & angle
        camera = new THREE.PerspectiveCamera(55, window.innerWidth / window.innerHeight, 1, 10000);
        camera.position.set(0, 420, 1150);
        camera.lookAt(new THREE.Vector3(0, 0, 0));

        // Setup Renderer
        renderer = new THREE.WebGLRenderer({
            canvas: canvas,
            antialias: true,
            powerPreference: "high-performance"
        });
        renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
        renderer.setSize(window.innerWidth, window.innerHeight);
        renderer.setClearColor(0xffffff, 1);

        // Build Particle Grid Arrays
        const numParticles = AMOUNTX * AMOUNTY;
        const positions = new Float32Array(numParticles * 3);
        const colors = new Float32Array(numParticles * 3);

        // Fetch colors dynamically from CSS variables
        const styles = getComputedStyle(document.documentElement);
        const particleColorVar = styles.getPropertyValue("--particle-color").trim() || "209, 213, 219";
        const rgb = particleColorVar.split(",").map(val => parseInt(val.trim()) / 255);

        let i = 0;
        for (let ix = 0; ix < AMOUNTX; ix++) {
            for (let iy = 0; iy < AMOUNTY; iy++) {
                const x = ix * SEPARATION - (AMOUNTX * SEPARATION) / 2;
                const z = iy * SEPARATION - (AMOUNTY * SEPARATION) / 2;

                positions[i * 3] = x;
                positions[i * 3 + 1] = 0;
                positions[i * 3 + 2] = z;

                colors[i * 3]     = rgb[0] !== undefined ? rgb[0] : 0.82;
                colors[i * 3 + 1] = rgb[1] !== undefined ? rgb[1] : 0.83;
                colors[i * 3 + 2] = rgb[2] !== undefined ? rgb[2] : 0.86;

                i++;
            }
        }

        geometry = new THREE.BufferGeometry();
        geometry.setAttribute("position", new THREE.BufferAttribute(positions, 3));

        // Create Particle Material
        material = new THREE.PointsMaterial({
            color: 0x000000,
            size: 7,
            transparent: true,
            opacity: 0.45,
            sizeAttenuation: true
        });

        particles = new THREE.Points(geometry, material);
        scene.add(particles);

        // Render & Wave Update Loop
        function animate() {
            animationId = requestAnimationFrame(animate);

            const positionAttribute = geometry.attributes.position;
            const posArray = positionAttribute.array;

            let index = 0;
            for (let ix = 0; ix < AMOUNTX; ix++) {
                for (let iy = 0; iy < AMOUNTY; iy++) {
                    posArray[index * 3 + 1] = 
                        Math.sin((ix + count) * 0.25) * 60 +
                        Math.sin((iy + count) * 0.4) * 60;
                    index++;
                }
            }

            positionAttribute.needsUpdate = true;
            renderer.render(scene, camera);
            count += 0.025; // Speed multiplier
        }

        function onWindowResize() {
            camera.aspect = window.innerWidth / window.innerHeight;
            camera.updateProjectionMatrix();
            renderer.setSize(window.innerWidth, window.innerHeight);
        }

        window.addEventListener("resize", onWindowResize, { passive: true });
        animate();

        // Memory cleanup
        window.addEventListener("beforeunload", () => {
            cancelAnimationFrame(animationId);
            window.removeEventListener("resize", onWindowResize);
            if (geometry) geometry.dispose();
            if (material) material.dispose();
            if (renderer) renderer.dispose();
        });
    }

    // Load Three.js dynamically if not already loaded by static script
    if (window.THREE) {
        startAnimation();
    } else {
        const script = document.createElement("script");
        script.src = "https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js";
        script.onload = startAnimation;
        script.onerror = () => console.error("Three.js failed to load.");
        document.head.appendChild(script);
    }
};

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
