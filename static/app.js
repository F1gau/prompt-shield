// ===================== THEME =====================

function toggleTheme(){
    document.body.classList.toggle("light");
    const light = document.body.classList.contains("light");
    localStorage.setItem("ps_theme", light ? "light" : "dark");
    updateThemeIcon();
}

function updateThemeIcon(){
    const icon = document.getElementById("themeIcon");
    if(!icon) return;

    if(document.body.classList.contains("light")){
        icon.className = "bi bi-sun-fill theme-btn";
    } else {
        icon.className = "bi bi-moon-stars-fill theme-btn";
    }
}

if(localStorage.getItem("ps_theme") === "light"){
    document.body.classList.add("light");
}
updateThemeIcon();


// ===================== MOBILE SIDEBAR =====================

const psBurger = document.getElementById("psBurger");
const psSidebar = document.getElementById("psSidebar");

if(psBurger && psSidebar){
    psBurger.addEventListener("click", () => {
        psSidebar.classList.toggle("open");
    });
}
