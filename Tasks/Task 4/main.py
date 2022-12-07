# Sukurkite klasę "Movie", kuri gebės sukurti objektus 3 savybėm ir 1 metodu. 
# Naudojant šią klasę sukurkite bent du skirtingus objektus.

# Savybės:
# title: string
# director: string
# budget: number

# Metodas: 
# wasExpensive() - jeigu filmo "budget" yra daugiau nei 100 000 000 mln USD, tada grąžins True, kitu atveju False. 

class Movie:
    def __init__(x, title, director, budget):
        x.title = title
        x.director = director
        x.budget = budget

    def wasExpensive(x):
        if x.budget > 100000000:
            print('True')
        else:
            print('False')

y = Movie("title1", "director1", 1)
z = Movie("title2", "director2", 100000001)

y.wasExpensive()
z.wasExpensive()




