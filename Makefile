# Dissecator Makefile
# Author: Matthieu Labas

# Compiler options
CC=javac
SOURCEPATH=src
BINPATH=bin
PRODPATH=prod

JARNAME=PCAPAnalyzer
MANIFEST=$(BINPATH)/META-INF/MANIFEST.MF
MAINCLASS=pcap.PCAPAnalyzer

EXESTUB=$(PRODPATH)/exestub.sh
EXE=dissecator

# Production
JFLAGS=-d $(BINPATH)
PROD_FLAGS=$(JFLAGS)
DEBUG_FLAGS=$(JFLAGS) -g

# Sources
SOURCES=$(shell find $(SOURCEPATH) -name "*.java")

all: production exe

production: clean $(SOURCES)
	@echo "Generating production version..."
	$(CC) $(PROD_FLAGS) $(SOURCES)

debug: clean $(SOURCES)
	@echo "Generating debug version..."
	$(CC) $(DEBUG_FLAGS) $(SOURCES)

exe: jar
	@echo "Packing executable $(EXE)..."
	@cat $(EXESTUB) $(PRODPATH)/$(JARNAME).jar > $(PRODPATH)/$(EXE) && chmod +x $(PRODPATH)/$(EXE)
	@echo "Executable packed."

jar: manifest
	@echo "Generating JAR $(JARNAME)..."
	@jar cfm $(PRODPATH)/$(JARNAME).jar $(MANIFEST) -C $(BINPATH) .
	@echo "JAR $(JARNAME) generated."

manifest:
	@echo "Generating manifest $(MANIFEST)"
	@mkdir -p $(shell dirname $(MANIFEST))
	@echo "Manifest-Version: 1.0" > $(MANIFEST)
	@echo "Main-Class: $(MAINCLASS)" >> $(MANIFEST)
	@echo "" >> $(MANIFEST)
	@echo "Manifest generated."

clean:
	@echo "Cleaning..."
	@rm -rf $(BINPATH)/*
	@echo "Cleaned."
