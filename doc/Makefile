
all:

gen: prereqs
	grip GettingStarted.md --export GettingStarted.html
	wkhtmltopdf GettingStarted.html GettingStarted.pdf

prereqs:
	apt install python-pip
	pip install grip
	apt install wkhtmltopdf
