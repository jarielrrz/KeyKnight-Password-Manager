let navbar = coument.getElementById("navigation");

let ShouldStickPosition = navbar.offsetTop;

function addOrRemoveStickyClass() {
    if (window.scrollY >= ShouldStickPosition) { 
        navbar.classList.add('sticky');
    } else {
        navbar.classList.remove('sticky');
    }
}

window.onscroll = () => {
    addOrRemoveStickyClass();
}

