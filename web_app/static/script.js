const form = document.getElementById("jobForm")
const loader = document.getElementById("loader")
const button = document.getElementById("analyzeBtn")
const textarea = document.querySelector("textarea")
const container = document.querySelector(".container")

/* ==========================
   Loading Animation
========================== */

if(form){

form.addEventListener("submit", function(){

loader.style.display = "block"

button.disabled = true
button.innerText = "Analyzing..."

const imageInput = document.querySelector('input[type="file"]')

if(imageInput && imageInput.files.length > 0){

loader.innerText = "Extracting text from screenshot..."

}
else if(textarea.value.includes("linkedin.com")){

loader.innerText = "Scanning LinkedIn profile..."

}else{

loader.innerText = "Analyzing job description..."

}

})

}


/* ==========================
   Dynamic Background Glow
========================== */

document.addEventListener("mousemove",(e)=>{

document.body.style.background =
`radial-gradient(circle at ${e.clientX}px ${e.clientY}px,#1a1a1a,#000)`

})

/* ==========================
   Probability Meter Animation
========================== */

window.addEventListener("load",()=>{

const meter = document.querySelector(".meter-bar")

if(meter){

let finalWidth = meter.style.width

meter.style.width="0%"

setTimeout(()=>{

meter.style.width=finalWidth

},300)

}

})
/* =========================
   AI Particle Background
========================= */

const canvas = document.getElementById("particleCanvas")
const ctx = canvas.getContext("2d")

canvas.width = window.innerWidth
canvas.height = window.innerHeight

let particles = []

const particleCount = 80

class Particle{

constructor(){

this.x = Math.random()*canvas.width
this.y = Math.random()*canvas.height

this.vx = (Math.random()-0.5)*1
this.vy = (Math.random()-0.5)*1

}

move(){

this.x += this.vx
this.y += this.vy

if(this.x<0 || this.x>canvas.width) this.vx *= -1
if(this.y<0 || this.y>canvas.height) this.vy *= -1

}

draw(){

ctx.beginPath()
ctx.arc(this.x,this.y,2,0,Math.PI*2)
ctx.fillStyle="white"
ctx.fill()

}

}

for(let i=0;i<particleCount;i++){
particles.push(new Particle())
}

function connectParticles(){

for(let i=0;i<particles.length;i++){

for(let j=i;j<particles.length;j++){

let dx = particles[i].x - particles[j].x
let dy = particles[i].y - particles[j].y

let distance = Math.sqrt(dx*dx+dy*dy)

if(distance<120){

ctx.beginPath()

ctx.strokeStyle="rgba(255,255,255,0.1)"
ctx.lineWidth=1

ctx.moveTo(particles[i].x,particles[i].y)
ctx.lineTo(particles[j].x,particles[j].y)

ctx.stroke()

}

}

}

}

function animate(){

ctx.clearRect(0,0,canvas.width,canvas.height)

particles.forEach(p=>{

p.move()
p.draw()

})

connectParticles()

requestAnimationFrame(animate)

}

animate()

window.addEventListener("resize",()=>{

canvas.width = window.innerWidth
canvas.height = window.innerHeight

})
/* ==========================
   AI Live Analysis Typing
========================== */

window.addEventListener("load",()=>{

const items = document.querySelectorAll(".analysis-item")

if(items.length === 0) return

let delay = 500

items.forEach((item,index)=>{

const text = item.dataset.text

setTimeout(()=>{

typeText(item,text,0)

},delay)

delay += text.length * 35 + 400

})

})

function typeText(element,text,i){

if(i < text.length){

element.innerHTML += text.charAt(i)

setTimeout(()=>{

typeText(element,text,i+1)

},20)

}

}
const fileInput = document.getElementById("fileUpload")

if(fileInput){

fileInput.addEventListener("change", function(){

const fileName = this.files[0]?.name

if(fileName){

document.querySelector(".upload-box p").innerText = fileName

}

})

}
fileInput.addEventListener("change", function(){

if(this.files.length > 0){

document.querySelector(".upload-box").style.borderColor = "#22c55e"
document.querySelector(".upload-box").style.boxShadow = "0 0 20px rgba(34,197,94,0.4)"

}

})