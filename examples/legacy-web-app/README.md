# Example: legacy web app

`legacy-dependencies.txt` pins versions of Flask, Django, Requests, Jinja2 and PyJWT from
2017-2019, and `assets.toml` lists it as an internet-facing, high-impact system. There is no
application here: the file only gives the dependency scan something to find.

It is deliberately not called `requirements.txt`, so GitHub's dependency graph and Dependabot do
not mistake it for a dependency of this repository.
