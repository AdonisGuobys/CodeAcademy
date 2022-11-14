y = ["Skaiciai: "]
while True:
    x = int(input("Iveskite skaiciu: "))

    if (x % 2) == 0:
        y.append(x)
    else:
        print(y)
        break