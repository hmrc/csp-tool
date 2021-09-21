
# csp-tool

Tools for handling and reviewing Content Security Policies in use. These are
written with automation in mind; in the absence of other apis or automated tools
(to date).

## License

This code is open source software licensed under the [Apache 2.0 License]("http://www.apache.org/licenses/LICENSE-2.0.html").

## Handy Content Security Policy references

- [Google direct checker - one by one method, not an api](https://csp-evaluator.withgoogle.com/)
- [Chrome Extension for insite checks](https://chrome.google.com/webstore/detail/csp-evaluator/fjohamlofnakbnbfjkohkbdigoodcejf?hl=en)
- [Google documentation fundamentals article](https://developers.google.com/web/fundamentals/security/csp)
- [Negative impacts of getting them wrong](https://www.netsparker.com/blog/web-security/negative-impact-incorrect-csp-implementations/)
- [Ionos blog post](https://www.ionos.co.uk/digitalguide/server/security/content-security-policy-how-websites-are-becoming-safer/)
- [The CSP spec (v3.0)](https://www.w3.org/TR/CSP3/)

## Dev: Using the source

The best entry point to understanding the code is the tests; reading the tests
should give you an idea of usecases. More docs will be incrementally added.

### Set up

For the best way to run the tests it's worth setting your environment up as
follows:

1) install pyenv (this will pick up the python version from .python-version)
2) install poetry (with the above version of python)
3) run `poetry install`
4) run `poetry show` to check project details

#### Useful resources

- [pyenv installation guide](https://github.com/pyenv/pyenv)
- [poetry installation guide](https://python-poetry.org/docs/#system-requirements)
- [...and useful blog](https://blog.jayway.com/2019/12/28/pyenv-poetry-saviours-in-the-python-chaos/)
- [poetry cli reference](https://python-poetry.org/docs/cli/)

### Run tests

on the command line from the project root run `poetry run pytest`

### Building source & wheel

on the command line from the project root run `poetry build`

### Consume in your project

If you can't find this package as `csp-tool` on pypi.org (and therefore pip) you
can still install it as a module in your consuming project by using

```bash
pip install /path/to/csp_tool-0.2.0-py3-none-any.whl
```

or list `./../relative/path/to/csp_tool-0.2.0-py3-none-any.whl` in your
requirements.txt file.

If you're using Poetry in your own project you can add this to your
`pyproject.toml`

```toml
[tool.poetry.dependencies]
my-package = { file = "path/to/csp_tool-0.2.0-py3-none-any.whl" }
```
