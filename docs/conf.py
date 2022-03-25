# Configuration file for the Sphinx documentation builder.
#
# This file does only contain a selection of the most common options. For a full list see
# the documentation:
# http://www.sphinx-doc.org/en/master/config

# -- Path setup --------------------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory, add these
# directories to sys.path here. If the directory is relative to the documentation root,
# use os.path.abspath to make it absolute, like shown here.
import os
import re
import sys

this_file_path = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(this_file_path, "..", "omemo"))

from version import __version__ as __version
from project import project     as __project

# -- Project information -----------------------------------------------------------------

project   = __project["name"]
author    = __project["author"]
copyright = f"{__project['year']}, {__project['author']}"

# The short X.Y version
version = __version["short"]
# The full version, including alpha/beta/rc tags
release = __version["full"]

# -- General configuration ---------------------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be extensions coming
# with Sphinx (named "sphinx.ext.*") or your custom ones.
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.viewcode",
    "sphinx.ext.napoleon",
    "sphinx_autodoc_typehints"
]

# Add any paths that contain templates here, relative to this directory.
templates_path = [ "_templates" ]

# List of patterns, relative to source directory, that match files and directories to
# ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = [ "_build", "Thumbs.db", ".DS_Store" ]

# -- Options for HTML output -------------------------------------------------------------

# The theme to use for HTML and HTML Help pages. See the documentation for a list of
# builtin themes.
html_theme = "sphinx_rtd_theme"

# Add any paths that contain custom static files (such as style sheets) here, relative to
# this directory. They are copied after the builtin static files, so a file named
# "default.css" will overwrite the builtin "default.css".
html_static_path = [ "_static" ]

# -- Autodoc Member Skipping -------------------------------------------------------------

private_name_regex = re.compile(r"^_\w+__")
def autodoc_skip_member_handler(app, what, name, obj, skip, options):
    """
    A very simple handler for the autodoc-skip-member event that skips everything "private", aka starting with
    double underscores. Everything else is left untouched.
    """

    if private_name_regex.match(name):
        return True

    return None

def setup(app):
    app.connect("autodoc-skip-member", autodoc_skip_member_handler)
