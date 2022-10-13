const backend = "https://634827000b382d796c6ac2ea.mockapi.io/api";
const submitForm = document.querySelector("form");

const postData = async (product) => {
    const response = await fetch(backend, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify(product),
        });
};

const addProduct = (event) => {
    event.preventDefault();
    const newName = document.getElementById("input-name");
    const newPrice = document.getElementById("input-price");
    const newPicture = document.getElementById("input-picture");
    const newInfo = document.getElementById("input-Info");
    const newLocation = document.getElementById("input-location");
    const product = {
        name: newName.value,
        price: newPrice.value,
        picture: newPicture.value,
        info: newInfo.value,
        location: newLocation.value
    };
    postData(product);
};
submitForm.addEventListener("submit", addProduct);

function homebutton() {
    location.href = ("./index.html");
  }
function add() {
    location.href = ("./index1.html");
  }
  