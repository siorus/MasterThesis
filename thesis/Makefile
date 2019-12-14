# makefile pro preklad LaTeX verze Bc. prace
# makefile for compilation of the thesis
# Autori / Authors: 2008 Michal Bidlo, 2016 Jaroslav Dytrych
# E-mail: dytrych AT fit vutbr cz
#===========================================
# asi budete chtit prejmenovat / you will probably rename:
CO=xkorce01-Aplikace-pro-generovani-a-overovani-konfiguraci-sitovych-zarizeni

clean:
	rm -f *.dvi *.log *.blg *.bbl *.toc *.aux *.out *.lof *.ptc *.gz *.bak *.lot *.lol *.toa *.nav *.snm
	rm -f text/*.dvi text/*.log text/*.blg text/*.bbl text/*.toc text/*.aux text/*.out text/*.lof text/*.ptc text/*.gz text/*.bak
	rm -f obrazky/*converted-to.pdf
	rm -f *.pdf
	rm -f *~

clean-nonpdf:
	rm -f *.dvi *.log *.blg *.bbl *.toc *.aux *.out *.lof *.ptc *.gz *.bak *.lot *.lol *.toa *.nav *.snm
	rm -f text/*.dvi text/*.log text/*.blg text/*.bbl text/*.toc text/*.aux text/*.out text/*.lof text/*.ptc text/*.gz text/*.bak
	rm -f obrazky/*converted-to.pdf
	rm -f *~

pack:
	tar czvf $(CO).tar.gz *.tex *.bib *.bst ./loga/* ./obrazky/* ./pdf/* ./text/* $(CO).pdf Makefile
	
# Pozor, vlna neresi vse (viz popis.txt) / Warning - vlna is not solving all problems (see description.txt)
vlna:
	vlna -l $(CO).tex
	vlna -l text/implementacia.tex
	vlna -l text/kyberneticka-bezpecnost.tex
	vlna -l text/navrh.tex
	vlna -l text/prevadzka-a-bezpecnost-sieti.tex
	vlna -l text/prilohy.tex
	vlna -l text/uvod.tex
	vlna -l text/zaver.tex

# Spocita normostrany / Count of standard pages
normostrany:
	echo "scale=2; `detex -n $(CO)-[01]*s.tex | wc -c`/1800;" | bc

