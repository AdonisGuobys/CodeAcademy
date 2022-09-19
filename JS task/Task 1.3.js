
const filtered = cars.filter((item) => {
  return item.Cylinders = 8;
});
const refiltered = filtered.filter((item) => {
  return item.Horsepower > 15;
});


console.log(refiltered);
