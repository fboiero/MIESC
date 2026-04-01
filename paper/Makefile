# Build the MIESC paper for arXiv submission
# Requires: pdflatex, bibtex (from texlive-full or similar)

PAPER = miesc-paper

.PHONY: all clean arxiv

all: $(PAPER).pdf

$(PAPER).pdf: $(PAPER).tex references.bib
	pdflatex $(PAPER)
	bibtex $(PAPER)
	pdflatex $(PAPER)
	pdflatex $(PAPER)

clean:
	rm -f $(PAPER).{aux,bbl,blg,log,out,pdf,synctex.gz,fls,fdb_latexmk}

# Create tarball for arXiv submission
arxiv: $(PAPER).pdf
	tar czf miesc-arxiv.tar.gz \
		$(PAPER).tex \
		references.bib \
		$(PAPER).bbl \
		Makefile
	@echo "Created miesc-arxiv.tar.gz for arXiv submission"
