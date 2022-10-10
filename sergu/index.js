g = document.createElement('div');
g.setAttribute("id", "Div1");


var i = 0;
function change() {
  var doc = document.getElementById("div1");
  var color = ["red", "green"];
  doc.style.backgroundColor = color[i];
  i = (i + 1) % color.length;
}
setInterval(change, 3000);