const goodFunc = () => {

  return new Promise((resolve, reject) => {

    setTimeout(() => {

      return resolve("works");

    }, 2000);

  });

};



goodFunc()

  .then((res) => {

    console.log("res", res);



    return "first then result";

  })

  .then((secondRes) => {

    console.log("secondRes", secondRes);

  })

  .catch((err) => {

    console.log("err", err);

  });s