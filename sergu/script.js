function myfunction() {
    alert("Function");
  }


  let array = [{
    Name: 'Cat',
    Price: 12,

  },
  {
    Name: 'Dog',
    Price: 24

  }
];

const template = document.querySelector('#template');
const clone = template.content.cloneNode(true);
const listElement = clone.querySelector('.template-list');


const lists = document.querySelector('.lists');

array.forEach(i => {
  let newClone = listElement.cloneNode(true)
  newClone.querySelector('.template-Name').textContent = i.Name;
  newClone.querySelector('.template-Price').textContent = i.Price;

  lists.append(newClone);
})