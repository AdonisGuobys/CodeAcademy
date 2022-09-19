const filtered = cars.filter((item) => {
  return item.Miles_per_Gallon > 0 ;
});

let theRemainder = cars.filter(x => !filtered.includes(x));

console.log(theRemainder);