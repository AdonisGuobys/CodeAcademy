y = []
x = input("Kiek zodziu? ")
x = int(x)

while x != 0:
    z = input("Iveskite zodzius: ")
    y.append(z)
    x = (x - 1)
if x == 0:
    print(y)