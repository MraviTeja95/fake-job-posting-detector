const form = document.getElementById("jobForm")
const loader = document.getElementById("loader")
const button = document.getElementById("analyzeBtn")
const textarea = document.querySelector("textarea")

// Form submit loading animation
if(form){

form.addEventListener("submit", function(){

loader.style.display = "block"

button.disabled = true
button.innerText = "Analyzing..."

if(textarea.value.includes("linkedin.com")){

loader.innerText = "Scanning LinkedIn profile..."

}else{

loader.innerText = "Analyzing job description..."

}

})

}

// Mouse interactive background
document.addEventListener("mousemove",(e)=>{

document.body.style.background =
`radial-gradient(circle at ${e.clientX}px ${e.clientY}px,#1a1a1a,#000)`

})

// Probability meter animation
window.addEventListener("load",()=>{

const meter = document.querySelector(".meter-bar")

if(meter){

let finalWidth = meter.style.width

meter.style.width = "0%"

setTimeout(()=>{

meter.style.width = finalWidth

},200)

}

})