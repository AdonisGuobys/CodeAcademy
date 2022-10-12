function myfunction() {
  alert("Function");
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
  {
   "Name": "Rustic Wooden Fish",
   "Price": "444.00",
   "Description": "Andy shoes are designed to keeping in mind durability as well as trends, the most stylish range of shoes & sandals",
   "Picture": "http://loremflickr.com/640/480/technics",
   "Location": "Danville",
   "id": "2"
  },
  {
   "Name": "Fantastic Granite Chair",
   "Price": "230.00",
   "Description": "The automobile layout consists of a front-engine design, with transaxle-type transmissions mounted at the rear of the engine and four wheel drive",
   "Picture": "http://loremflickr.com/640/480/technics",
   "Location": "Warwick",
   "id": "3"
  },
  {
   "Name": "Recycled Soft Sausages",
   "Price": "553.00",
   "Description": "The Nagasaki Lander is the trademarked name of several series of Nagasaki sport bikes, that started with the 1984 ABC800J",
   "Picture": "http://loremflickr.com/640/480/technics",
   "Location": "Hempstead",
   "id": "4"
  },
  {
   "Name": "Handcrafted Frozen Car",
   "Price": "966.00",
   "Description": "Boston's most advanced compression wear technology increases muscle oxygenation, stabilizes active muscles",
   "Picture": "http://loremflickr.com/640/480/technics",
   "Location": "Katherynstead",
   "id": "5"
  },
  {
   "Name": "Refined Metal Towels",
   "Price": "325.00",
   "Description": "The Football Is Good For Training And Recreational Purposes",
   "Picture": "http://loremflickr.com/640/480/technics",
   "Location": "Hickleshire",
   "id": "6"
  },
  {
   "Name": "Awesome Metal Sausages",
   "Price": "836.00",
   "Description": "The Football Is Good For Training And Recreational Purposes",
   "Picture": "http://loremflickr.com/640/480/technics",
   "Location": "Brakusmouth",
   "id": "7"
  },
  {
   "Name": "Gorgeous Cotton Towels",
   "Price": "186.00",
   "Description": "Ergonomic executive chair upholstered in bonded black leather and PVC padded seat and back for all-day comfort and support",
   "Picture": "http://loremflickr.com/640/480/technics",
   "Location": "Thompsonbury",
   "id": "8"
  },
  {
   "Name": "Sleek Soft Chips",
   "Price": "902.00",
   "Description": "The automobile layout consists of a front-engine design, with transaxle-type transmissions mounted at the rear of the engine and four wheel drive",
   "Picture": "http://loremflickr.com/640/480/technics",
   "Location": "Heidenreichtown",
   "id": "9"
  },
  {
   "Name": "Incredible Concrete Shoes",
   "Price": "15.00",
   "Description": "Andy shoes are designed to keeping in mind durability as well as trends, the most stylish range of shoes & sandals",
   "Picture": "http://loremflickr.com/640/480/technics",
   "Location": "Lilaton",
   "id": "10"
  }
 ]

const divTag = document.querySelector('.MainPage')
for (let i = 0; i < array.length; ++i) {
const imgTag = document.createElement('img')  
imgTag.setAttribute('src', array[i].Picture)
divTag.append(array[i].Name, array[i].Price, imgTag)
}

