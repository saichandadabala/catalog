from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from databse_setup import Bikes, Base, Types, User


engine = create_engine('sqlite:///Biketypes.db')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


User1 = User(name="admin", email="aichandadabala@gmail.com")
session.add(User1)
session.commit()


# Types Of Bikes
Cruiser = Bikes(name="Cruiser", user_id=1)

session.add(Cruiser)
session.commit()


type1 = Types(name="2019 Star Motorcycles V Star 250",
              description="The 2019 V Star 250 is part of Star Motorcycles's"
              "cruiser lineup. Key measurements include: 58.7 in"
              "wheelbase, 27.0 in. seat height, and 326 pounds wet weight."
              "Prices start at $4, 349.",
              price="$4, 349", category=Cruiser, user_id=1)

session.add(type1)
session.commit()


type2 = Types(name="2019 Suzuki Boulevard C90T",
              description="The 2019 Boulevard C90T is part of Suzuki's"
              "cruiser lineup. Key measurements include: 65.9 in"
              "wheelbase, 28.3 in. seat height, and 800 pounds"
              "wet weight. Prices start at $13, 049.",
              price="$13 ,049", category=Cruiser, user_id=1)

session.add(type2)
session.commit()

type3 = Types(name="2019 Suzuki Boulevard C50",
              description="The 2019 Boulevard C50 is part of Suzuki's"
              "cruiser lineup."
              "Key measurements include: 65.2 in wheelbase, 27.6 in."
              "seat height, and 611 pounds wet weight."
              "Prices start at $8, 299.",
              price="$8, 299", category=Cruiser, user_id=1)

session.add(type3)
session.commit()

# types of Bikes
Street = Bikes(name="Street", user_id=1)

session.add(Street)
session.commit()
# types of bikes
Off_Road = Bikes(name="Off-Road", user_id=1)

session.add(Off_Road)
session.commit()
print "data has been added sucessfully!!"
