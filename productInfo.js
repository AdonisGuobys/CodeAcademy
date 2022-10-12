const destinationId = localStorage.getItem("destinationId");

let x = function () {
    window.open("./index.html", "_self");
}


const getOneDestination = () => {
    fetch(
        `https://634438fc242c1f347f81b2a1.mockapi.io/products/${destinationId}`
    )
        .then((response) => {
            return response.json();
        })
        .then((data) => {
            console.log(data);

            const prodPhoto = document.getElementById("productPhoto");
            prodPhoto.src = data.avatar;

            const prodName = document.getElementById("productName");
            prodName.innerHTML = data.name;

            const prodPrice = document.getElementById("productPrice");
            prodPrice.innerHTML = "Kaina " + data.price + " €";


            const prodDescription = document.getElementById("productDescription");
            prodDescription.innerHTML = data.description;

            const productLocation = document.getElementById("productLocation");
            productLocation.innerHTML = data.location;

            const removeItemButton = document.createElement("button");
            removeItemButton.classList.add("remove-item");
            removeItemButton.innerHTML = "Ištrinti skelbimą";
            removeItemButton.addEventListener("click", () => {
                deleteItem(data.id);
            });
            additionalInfoWrapper.append(removeItemButton)

        });
};

getOneDestination();

const deleteItem = (id) => {
    fetch(
        `https://634438fc242c1f347f81b2a1.mockapi.io/products/${id}`,
        {
            method: "DELETE",
            headers: {
                Accept: "application/json",
                "Content-Type": "application/json",
            },
        }
    )
        .then((res) => {
            setTimeout(() => {
                const deleteMsg = document.createElement("h3")
                deleteMsg.innerHTML = "Skelbimas buvo ištrintas"
                deleteMsg.classList.add("remove-msg")
                document.body.append(deleteMsg)
            }, 2000)
        })
        .then((res) => {
            setTimeout(() => {
                x()
            }, 6000);
        })
        .catch((err) => {
            console.log("err", err);
        });
};

console.log("test")

