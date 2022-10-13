//const backend = "https://6345871839ca915a6901ab38.mockapi.io/api/api/";
const backend = "https://634438fc242c1f347f81b2a1.mockapi.io/products";
const apidata = {};
const productsContainer = document.getElementById("products");



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

    //button additional info
    const buttonSection = document.createElement("div");
    buttonSection.classList.add("button-section");

    const button = document.createElement("button");
    button.classList.add("button");
    button.innerHTML = "Daugiau info"
    //local storage

    button.addEventListener("click", () => {
        localStorage.setItem("destinationId", products.id);
        window.location.replace("./productinfo.html");
      });
    
    div.append(productName, productImg, productPrice, buttonSection)
    buttonSection.append(button)
};

const fetchProducts = async () => {
    const response = await fetch(backend);
        apidata.products = await response.json();
        apidata.products.sort((a, b) => a.price - b.price)
        apidata.products.forEach((product) => createProduct(product));
};
fetchProducts();
