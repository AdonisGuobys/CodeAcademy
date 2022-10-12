const END_POINT = "https://634438fc242c1f347f81b2a1.mockapi.io/products";
const submitForm = document.querySelector("form");

const postData = async (product) => {
    const alertMsg = document.getElementById("alert");
    try {
        const response = await fetch(END_POINT, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(product),
        });
        if (response.ok) {
            alertMsg.innerHTML = "Prekė įkelta sėkmingai!";
        }
    } catch (error) {
        alertMsg.innerHTML = `There was an error!\n${error}`;
    }
};

const addProduct = (event) => {
    event.preventDefault();
    const productNameInput = document.getElementById("product-name");
    const productPriceInput = document.getElementById("product-price");
    const productPhotoInput = document.getElementById("product-photo");
    const productDescriptionInput = document.getElementById("product-description");
    const productLocationInput = document.getElementById("product-location");

    const product = {
        name: productNameInput.value,
        price: productPriceInput.value,
        avatar: productPhotoInput.value,
        description: productDescriptionInput.value,
        location: productLocationInput.value



    };
    postData(product);
};

submitForm.addEventListener("submit", addProduct);