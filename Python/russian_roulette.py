name = input("What is your name? ")
lucky_number = input("Welcome " + name + ", choose your lucky number: ")
lucky_number = int(lucky_number)

import random
number = random.randint(1, 6)
if number == lucky_number:
    print("Dead...")
else:
    print("Its: " + str(number) + " , you survived...")
    