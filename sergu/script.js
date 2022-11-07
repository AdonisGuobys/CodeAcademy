const backend = "https://634827000b382d796c6ac2ea.mockapi.io/api";
const apidata = {};
const productsContainer = document.getElementById("products");

const fetchProducts = async () => {
  const response = await fetch(backend);
      apidata.products = await response.json();
      apidata.products.sort((a, b) => a.price - b.price)
      apidata.products.forEach((product) => createProduct(product));
};
fetchProducts();

const createProduct = (products) => {
    const div = document.createElement("div");
    div.classList.add("product-card");
    productsContainer.append(div);

    const productImg = document.createElement("img");
    productImg.src = products.picture
    const productName = document.createElement("h1");
    productName.innerHTML = products.name;
    const productPrice = document.createElement("h1");
    productPrice.innerHTML = products.price + " $";

    const buttonSection = document.createElement("div");
    buttonSection.classList.add("button-section");

    const button = document.createElement("button");
    button.classList.add("button");
    button.innerHTML = "Buy"
    button.style.width ='200px';
    button.style.height ='50px';
    button.style.backgroundColor = 'silver';

    button.addEventListener("click", () => {
      localStorage.setItem("id", products.id);
      window.location.replace("./index2.html");
    });

    div.append(productName, productImg, productPrice, buttonSection)
    buttonSection.append(button)
};

function homebutton() {
  location.href = ("./index.html");
}

function add() {
  location.href = ("./index1.html");
}
