SARIF formatter for Bandit
==========================

Overview
========

``bandit_sarif_formatter`` is a `report formatter <https://bandit.readthedocs.io/en/latest/formatters/index.html>`_
for `Bandit <https://bandit.readthedocs.io/en/latest/>`_, a security analyzer for Python.
It produces output in the `Static Analysis Results Interchange Format (SARIF) Version 2.1.0 <https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01>`_ file format,
an `OASIS <https://www.oasis-open.org>`_ `Committee Specification <https://www.oasis-open.org/news/announcements/static-analysis-results-interchange-format-sarif-v2-1-0-from-the-sarif-tc-is-an-a>`_.

To learn more about SARIF and find resources for working with it, you can visit the `SARIF Home Page <http://sarifweb.azurewebsites.net/>`_.

Building
========

To build the ``bandit_sarif_formatter`` package, see the `Python Packaging Authority <https://www.pypa.io/en/latest/>`_'s instructions for
`Packaging Python Projects`_, in particular the section "Generating distribution archives."

.. _Packaging Python Projects: https://packaging.python.org/tutorials/packaging-projects/

Briefly: run the following commands from the project root directory::

    python -m pip install --user --upgrade setuptools wheel
    python setup.py sdist bdist_wheel

The `source distribution <https://packaging.python.org/glossary/#term-source-distribution-or-sdist>`_ (``.tar.gz``)
and `wheel <https://packaging.python.org/glossary/#term-wheel>`_-style `built distribution <https://packaging.python.org/glossary/#term-built-distribution>`_ (``.whl``) packages
appear in the ``dist/`` directory.

Publishing
==========

To publish the ``bandit_sarif_formatter`` package, see the section "Uploading the distribution archives" and "Next steps" in
`Packaging Python Projects`_.

Briefly: log in to https://pypi.org with the **TODO** account, and then run the following commands from the project root directory::

    python -m pip install --user --upgrade twine
    python -m twine upload dist/*

Installing
==========

To install the ``bandit_sarif_formatter`` package, run the command::

    python -m pip install bandit_sarif_formatter

Using
=====

To generate SARIF output from Bandit, run the command::

    bandit --format sarif [targets [targets ...]] --output out.sarif

CWE Extension
=============

Added the Common Weakness Enumeration (CWE) taxonomy. The short and long description for the CWEs are retrieved from a JSON file which is a slimmed down version of the official comprehensive CWE XML from MITRE. The JSON contains information about all CWEs.

Contributing
============

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the `Microsoft Open Source Code of Conduct <https://opensource.microsoft.com/codeofconduct>`_.
For more information see the `Code of Conduct FAQ <https://opensource.microsoft.com/codeofconduct/faq/>`_ or
contact `opencode@microsoft.com <mailto:opencode@microsoft.com>`_ with any additional questions or comments.
