function myfunction() {
  alert("Function");
}
function myfunction1() {
  location.href = ("./index.html");
}


const array = [
  {
   "Name": "Generic Bronze Salad",
   "Price": "456.00",
   "Description": "The Nagasaki Lander is the trademarked name of several series of Nagasaki sport bikes, that started with the 1984 ABC800J",
   "Picture": "http://loremflickr.com/640/480/technics",
   "Location": "Amberbury",
   "id": "1"
  },
 ]



  const divTag = document.querySelector('.MainPage');
  for (let i = 0; i < array.length; ++i) {
  productid = document.createElement('div');
  imgTag = document.createElement('img'); 
  imgTag.setAttribute('src', array[i].Picture);
  linkas=document.createElement('a'); 
  linkas.setAttribute('href', "./index1.html");
  productid.append(array[i].Name,linkas,array[i].Price);
  linkas.appendChild(imgTag);
  divTag.append(productid);
  }