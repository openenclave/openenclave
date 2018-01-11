Using Doxygen in OpenEnclave
============================

This short document explains how to use Doxygen within OpenEnclave.

## Overview

Doxygen is used to extract documentation from the OpenEnclave source code.
This directory contains a makefile for building all Doxygen output formats
including:

- HTML (html directory)
- XML (xml directory)
- LaTeX (latex directory)
- Markdown (md directory)

The xml2md tool is used to generate Markdown format (from Doxygen-generated
XML files). The generated Markdown files are the only ones that are checked
into the Github repository. This allows one to browse the documentation from
the Github site.

To update the generated documentation, create the cmake build tree by using
the instructions in [Getting Started with OpenEnclave](doc/GettingStarted.md).
Assuming that _/build_ is the root of the cmake build tree, a successful make
will build the HTML, LaTeX and XML reference documentation by default. You can
also make the documentation directly:

```
build$ make refman
```

The resulting documentation can be found in the cmake tree under:

```
build/doc/refman
```

To update the generated Markdown files in the source tree for commit into
Github, you will need to also run the following from the cmake build root:

```
build$ make refman-source
```

## Adding headers files to Doxygen

To add new header files to be processed by Doxygen, edit this file (in the
current directory).

```
doxygen.conf
```

Append new sources to the **INPUT** variable.

## Source-code documentation conventions

OpenEnclave uses the Doxygen Markdown style througout the sources. To learn
more about Doyxgen Markdown, see:

  [Doxygen Markdown Support](https://www.stack.nl/~dimitri/doxygen/manual/markdown.html)

The sections below explain the basics.

**Caution:** the xml2md tool only supports the Mardown features described below.

### Comment blocks

In OpenEnclave, Doxygen comment blocks are defined as follows.

```
/**
 *
 *
 */
```

### Brief description

The brief description is the first sentence that appears in the comment block,
terminated by a period.

```
/**
 * This is my brief description.
 */
```

### Detailed description

The detailed description follows the brief description.

```
/**
 * This is my brief description.
 *
 * This is my detailed description. It may contain many sentences.
 */
```

### Parameters

Parameters should be introduced as follows.

```
/**
 * ...
 *
 * @param param1 This is my first parameter.
 * @param param2 This is my second parameter.
 */
```
#### Return values

Return values may be specified as a list of paragraphs (**@retval**) or
as a single paragrah (**@returns**).

Here's an example of a list of paragraphs:

```
/**
 * ...
 *
 * @retval SUCCESS The function was successful.
 * @retval FAILED The function failed.
 */
```

Here's an example of a single paragraph:

```
/**
 * ...
 *
 * @returns Returns OK on success.
 */
```

### Emphasis

To emphasize text (italics), use single asterisks as follows.

```
/**
 * This is my *emphasis* example.
 *
 */
```

### Boldface

To bold text, use double asterisks as follows.

```
/**
 * This is my *bold* example.
 *
 */
```

### Lists

Lists are introduced by the hyphen character as follows.

```
/**
 * ...
 *
 * This is my list:
 * - Sunday
 * - Monday
 * - Tuesday
 * - Wednesday
 * - Thursday
 * - Friday
 * - Saturday
 *
 */
```

### Verbatim

To define a verbatim block of text, separate it by blank lines and indent it.
For example.

```
/**
 * ...
 *
 * This is my verbatim text:
 *
 *   This is my verbatim block of text.
 *
 * Continue with normal text.
 *
 */
```

