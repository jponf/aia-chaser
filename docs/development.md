# Development

First of all, you must have *Make* and one of the following tool groups
installed and on your `$PATH`:

 * [Pyenv](https://github.com/pyenv/pyenv)
 * [Poetry](https://python-poetry.org/docs/#installation) (version 2 or newer)

 or

 * [Mise](https://mise.jdx.dev/)

Then, open a terminal on the project's directory and run:

```console
sh scripts/setup_dev_env
```

Once the script finishes running the basic tools should be ready, proceed with

```
make init
```

this will run some additional tests, create the virtual environment, install
the project dependencies and configure git hooks.


## Coding Guideline

There are many details to keep track of to guarantee that all code follows the
same style, for that we have tools. This project uses *black* and *ruff* to
verify that all code adheres to the same rules. Additionally, pre-commit hooks
and CI pipeline steps are in place to run them automatically.

Moreover, we like to add types to or code and check it with *mypy* (there are
hooks for it too). We like it because *typing* your Python code helps catch some
potential bugs, which may go unnoticed until that code is executed, and it also
helps other developers use the package by providing type-hinting in modern editors.

As always tools can only get so far, these tools allow disabling rules on a per-file
and per-line basis, just be mindful and do so when strictly necessary.
