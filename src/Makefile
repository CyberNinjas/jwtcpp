BINARIES = jwtcpp
SOURCES = main.cpp jwt.cpp utils.cpp
TARGETS = $(BINARIES)

LINK.o = g++

CFLAGS += -Werror -pedantic

CXXFLAGS += $(CFLAGS)

.PHONY : clean

all: $(TARGETS)

jwtcpp: clean
	g++ -o jwtcpp main.cpp jwt.cpp utils.cpp -ljansson -lcryptopp -lpthread $(CXXFLAGS) -I ../include/ -std=c++11

tests: clean
	g++ -o tests main.cpp jwt.cpp utils.cpp tests.cpp -ljansson -lcryptopp -lpthread -lunittest++ $(CXXFLAGS) -I ../include/ -std=c++11

clean: 
	rm -f *.exe* *.o $(TARGETS) *.bak *~
