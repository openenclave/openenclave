refman
======

This directory builds all Doxygen output formats including:

- HTML (.html)
- XML (.xml)
- latex (.tex)
- Markdown (.md)

The dox2md tool creates the Markdown files (.md) from the XML files above.

To makefile provides the following rules:

- make -- builds all the documentation formats
- make clean -- cleans up all temporarily generated files
- make browse -- launch firefox to browse the HTML documentation
- make push -- update the Git repository with the generated .md files 

