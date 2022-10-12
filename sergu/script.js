const backend = "https://6345871839ca915a6901ab38.mockapi.io/api/api/";
const api = {};
const productContainer = document.getElementsByClassName("products");

const createProduct = (products) => {
  const div = document.createElement("div");
  div.classList.add("product-card");
  productContainer.append(div);

  const productName = document.createElement("h1");
  productName.innerHTML = products.name;
  const productPrice = document.createElement("h1");
  productPrice.innerHTML = "Kaina " + products.price + " €";
  const productImg = document.createElement("img");
  productImg.src = products.avatar

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
  


  div.append(productName, productPrice, productImg, buttonSection)
  buttonSection.append(button)
};

const fetchProducts = async () => {
  try {
      const response = await fetch(backend);
      if (response.ok) {
          productsData.products = await response.json();
          productsData.products.sort((a, b) => a.price - b.price)
          productsData.products.forEach((product) => createProduct(product));
      }
  } catch (error) {
      console.error(error);
  }
};

fetchProducts();

function myfunction() {
  alert("Function to add");
}
function myfunction1() {
  location.href = ("./index.html");
}
