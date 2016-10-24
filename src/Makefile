BINARIES = jwtcpp
SOURCES = jwt.cpp utils.cpp
TARGETS = $(BINARIES)

LINK.o = g++

CFLAGS += -Werror -pedantic

CXXFLAGS += $(CFLAGS)

.PHONY : clean

all: $(TARGETS)

jwtcpp: clean
	g++ -c jwt.cpp utils.cpp -ljansson -lcryptopp -lpthread $(CXXFLAGS)

clean: 
	rm -f *.exe* *.o $(TARGETS) *.bak *~
